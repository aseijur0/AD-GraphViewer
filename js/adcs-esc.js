// AD CS escalation (ESC) reasoning worked out inside the viewer.
//
// BloodHound CE post-processing emits ADCSESC* edges, but a raw SharpHound
// collection only carries the certificate-template / enterprise-CA settings and
// the enrollment ACLs. This module turns those raw inputs into clearly labelled
// "potential" escalation relationships (ESC1/2/3/4/6/9/13/15), each marked
// computed:true the same way graph-index.js derives DCSync, so the suggested
// attack paths can traverse AD CS without external post-processing.
//
// The same ESC definitions drive the Inspector summary (pass/fail per condition),
// the "who can effectively enroll" view, and the defensive guidance.
// Everything here is advisory: a computed condition is a prompt to validate the
// template, its publication, and effective enrollment rights, not proof of a
// working exploit.

// Extended Key Usage / application-policy OIDs that matter for the computed
// checks. A template that enables authentication (client auth, smart-card
// logon, PKINIT) can be used to obtain a logon certificate.
var ESC_EKU_ANY_PURPOSE = '2.5.29.37.0';
var ESC_EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
var ESC_EKU_SMARTCARD_LOGON = '1.3.6.1.4.1.311.20.2.2';
var ESC_EKU_PKINIT_CLIENT = '1.3.6.1.5.2.3.4';
var ESC_EKU_CERT_REQUEST_AGENT = '1.3.6.1.4.1.311.20.2.1';
var ESC_AUTH_EKUS = [ESC_EKU_ANY_PURPOSE, ESC_EKU_CLIENT_AUTH, ESC_EKU_SMARTCARD_LOGON, ESC_EKU_PKINIT_CLIENT];

// Rights that grant certificate enrollment on a template or CA. Full control
// (GenericAll) and AllExtendedRights include enrollment.
var ESC_ENROLL_RIGHTS = ['enroll', 'autoenroll', 'allextendedrights', 'genericall'];
// Rights that let a principal reshape a template (ESC4 prerequisite).
var ESC_TEMPLATE_CONTROL_RIGHTS = ['genericall', 'genericwrite', 'writedacl', 'writeowner', 'owns',
  'writepkinameflag', 'writepkienrollmentflag'];
// Rights over an enterprise CA that enable issuing/forging certificates (ESC7):
// ManageCA and ManageCertificates directly, or full control of the CA object.
var ESC7_CA_CONTROL_RIGHTS = ['manageca', 'managecertificates', 'genericall', 'owns', 'writedacl', 'writeowner'];

function escLowerProps(node) {
  // normalizedNodeFields (graph-index.js) lowercases every property key and
  // caches per graph revision, so this is cheap to call repeatedly.
  return node && typeof normalizedNodeFields === 'function'
    ? normalizedNodeFields(node).properties
    : (node && node.properties) || {};
}

function escFirstProp(props, names) {
  for (var i = 0; i < names.length; i++) {
    if (Object.prototype.hasOwnProperty.call(props, names[i])) return props[names[i]];
  }
  return undefined;
}

function escBool(value) {
  return value === true || value === 'true' || value === 1 || value === '1';
}

// Collect the application-policy / EKU OIDs a template advertises, across the
// several property names different collector versions have used.
function escEkuList(props) {
  var raw = [].concat(
    props.effectiveekus || [], props.ekus || [],
    props.certificateapplicationpolicy || props.certificateapplicationpolicies || [],
    props.applicationpolicies || props.applicationpolicy || []
  );
  var out = [];
  raw.forEach(function (value) {
    if (value === null || value === undefined) return;
    var oid = String(value).trim();
    if (oid && out.indexOf(oid) === -1) out.push(oid);
  });
  return out;
}

function escEkuIncludes(ekus, oid) {
  return ekus.indexOf(oid) !== -1;
}

function escHasAuthEku(ekus) {
  // An empty EKU list means "any purpose" for schema-aware templates, but we do
  // not infer authentication from an absent list to avoid false positives when
  // EKUs were simply not collected.
  for (var i = 0; i < ESC_AUTH_EKUS.length; i++) {
    if (escEkuIncludes(ekus, ESC_AUTH_EKUS[i])) return true;
  }
  return false;
}

// Normalised certificate-template settings used by every ESC check.
function escTemplateFlags(template) {
  var p = escLowerProps(template);
  var ekus = escEkuList(p);
  var sigs = Number(escFirstProp(p, ['authorizedsignatures', 'authorizedsignaturesrequired', 'rasignaturesrequired']) || 0);
  var schema = Number(escFirstProp(p, ['schemaversion', 'templateschemaversion']));
  return {
    enrolleeSuppliesSubject: escBool(escFirstProp(p, ['enrolleesuppliessubject', 'enrolleesuppliessan'])),
    authenticationEnabled: escBool(escFirstProp(p, ['authenticationenabled'])) || escHasAuthEku(ekus),
    requiresManagerApproval: escBool(escFirstProp(p, ['requiresmanagerapproval', 'enrollmentflagpendallrequests'])),
    authorizedSignatures: isFinite(sigs) ? sigs : 0,
    schemaVersion: isFinite(schema) ? schema : null,
    noSecurityExtension: escBool(escFirstProp(p, ['nosecurityextension', 'enrollmentflagnosecurityextension'])),
    ekus: ekus,
    enabled: escFirstProp(p, ['enabled']) !== false
  };
}

// szOID_NTDS_CA_SECURITY_EXT — the SID security extension. A CA that disables it
// globally (ESC16) strips it from every issued certificate.
var ESC_SID_SECURITY_EXT_OID = '1.3.6.1.4.1.311.25.2';

function escCaFlags(ca) {
  var p = escLowerProps(ca);
  var disabledExts = [].concat(escFirstProp(p, ['disabledextensions', 'disableextensionlist']) || []).map(String);
  var securityExtensionDisabled = escBool(escFirstProp(p, ['securityextensiondisabled', 'disablesecurityextension'])) ||
    disabledExts.indexOf(ESC_SID_SECURITY_EXT_OID) !== -1;
  return {
    userSpecifiesSan: escBool(escFirstProp(p, ['isuserspecifiessanenabled'])),
    roleSeparation: escBool(escFirstProp(p, ['roleseparationenabled'])),
    hasEnrollmentAgentRestrictions: escBool(escFirstProp(p, ['hasenrollmentagentrestrictions'])),
    webEnrollmentEndpoints: [].concat(escFirstProp(p, ['httpenrollmentendpoints']) || []),
    securityExtensionDisabled: securityExtensionDisabled,
    disabledExtensions: disabledExts
  };
}

// Template-local condition predicates. Publication and effective enrollment are
// applied by the caller; ESC4 (control) and ESC13 (policy group link) also need
// relationship context and are handled where those edges are available.
var ESC_TEMPLATE_CONDITION = {
  ESC1: function (f) { return f.enrolleeSuppliesSubject && f.authenticationEnabled && !f.requiresManagerApproval && f.authorizedSignatures === 0; },
  ESC2: function (f) { return escEkuIncludes(f.ekus, ESC_EKU_ANY_PURPOSE) && !f.requiresManagerApproval && f.authorizedSignatures === 0; },
  ESC3: function (f) { return escEkuIncludes(f.ekus, ESC_EKU_CERT_REQUEST_AGENT) && !f.requiresManagerApproval && f.authorizedSignatures === 0; },
  ESC9: function (f) { return f.noSecurityExtension && f.authenticationEnabled && !f.requiresManagerApproval && f.authorizedSignatures === 0; },
  ESC13: function (f) { return !f.requiresManagerApproval && f.authorizedSignatures === 0; },
  ESC15: function (f) { return f.schemaVersion === 1 && f.enrolleeSuppliesSubject && !f.requiresManagerApproval && f.authorizedSignatures === 0; }
};

function escKind(escId) { return 'ADCS' + escId; }

// Human-facing metadata: what the condition is, the settings that matter, and
// the defensive context (why it is risky, which Windows event IDs show related
// certificate activity, and how to remediate).
var ESC_DEFINITIONS = {
  ESC1: {
    scope: 'template', title: 'ESC1 — Enrollee-supplied subject on an authentication template',
    summary: 'A low-privileged enroller can request a logon certificate for any account because the template lets the requester supply the subject/SAN and enforces no approval or signatures.',
    eventIds: '4886/4887 (certificate request received/issued), 4899/4900 (template or its security changed)',
    fix: 'Turn on manager approval, clear the "supply subject in request" flag (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), and remove broad enrollment rights.'
  },
  ESC2: {
    scope: 'template', title: 'ESC2 — Any Purpose (or SubCA) EKU template',
    summary: 'The template issues certificates usable for any purpose, including client authentication, so an enrolled certificate can be repurposed for logon or request-on-behalf.',
    eventIds: '4886/4887 (certificate request received/issued)',
    fix: 'Replace the Any Purpose EKU with only the EKUs the template needs, require manager approval, and restrict enrollment.'
  },
  ESC3: {
    scope: 'template', title: 'ESC3 — Enrollment Agent template',
    summary: 'The template grants the Certificate Request Agent EKU, so an enroller can request certificates on behalf of other principals (then authenticate as them).',
    eventIds: '4886/4887 (request received/issued), 4898 (certificate template loaded)',
    fix: 'Configure enrollment-agent restrictions on the CA, require manager approval, and remove broad enrollment rights.'
  },
  ESC4: {
    scope: 'template', title: 'ESC4 — Writable certificate template',
    summary: 'A principal can modify the template’s configuration or DACL and reshape it into an ESC1-style template, then enroll.',
    eventIds: '4899/4900 (template or template security changed), 5136 (directory object modified)',
    fix: 'Remove GenericAll/GenericWrite/WriteDacl/WriteOwner and name/enrollment-flag write rights from non-administrators and restore the template owner to a tier-0 group.'
  },
  ESC16: {
    scope: 'ca', title: 'ESC16 — CA omits the SID security extension (globally)',
    summary: 'The CA is configured to strip the SID security extension (szOID_NTDS_CA_SECURITY_EXT) from every certificate it issues, so any enrollable authentication template becomes an ESC9-style account-mapping path when certificate binding on the DCs is weak.',
    eventIds: '4886/4887 (request received/issued), 4882 (CA configuration changed), KDC 39/41 (certificate mapping) in the System log',
    fix: 'Remove szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) from the CA’s DisableExtensionList (certutil -setreg policy\\\\DisableExtensionList), restart certsvc, and set StrongCertificateBindingEnforcement = 2 on domain controllers.'
  },
  ESC7: {
    scope: 'ca', title: 'ESC7 — CA administration / takeover',
    summary: 'A principal that can administer the CA (ManageCA / ManageCertificates) or take over the CA object can issue or approve certificates for any account, or enable other ESC conditions — equivalent to domain compromise when the CA is trusted for authentication.',
    eventIds: '4886/4887 (request received/issued), 4888 (denied), 4882 (CA security permissions changed)',
    fix: 'Remove ManageCA / ManageCertificates and write/owner rights over the CA from non-administrators; enable role separation and manager approval.'
  },
  ESC6: {
    scope: 'ca', title: 'ESC6 — CA accepts requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)',
    summary: 'The CA honours a requester-supplied Subject Alternative Name on any request, so any enrollable authentication template published to it behaves like ESC1.',
    eventIds: '4886/4887 (request received/issued), 4882 (CA security permissions changed)',
    fix: 'Clear the flag: certutil -config "<CA>" -setreg policy\\\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then restart certsvc; require manager approval on authentication templates.'
  },
  ESC9: {
    scope: 'template', title: 'ESC9 — No security extension (szOID_NTDS_CA_SECURITY_EXT omitted)',
    summary: 'The template omits the SID security extension, enabling certificate-mapping abuse when combined with weak/compatibility certificate binding on the DCs.',
    eventIds: '4886/4887 (request received/issued), KDC 39/41 (certificate mapping) in the System log',
    fix: 'Remove CT_FLAG_NO_SECURITY_EXTENSION from the template and set StrongCertificateBindingEnforcement = 2 on domain controllers.'
  },
  ESC13: {
    scope: 'template', title: 'ESC13 — Issuance policy linked to a privileged group',
    summary: 'The template carries an issuance policy whose OID is linked (msDS-OIDToGroupLink) to a group, so enrolling grants the enroller that group’s membership.',
    eventIds: '4886/4887 (request received/issued)',
    fix: 'Remove the OID-to-group link (msDS-OIDToGroupLink) or the issuance policy from the template, and restrict enrollment.'
  },
  ESC15: {
    scope: 'template', title: 'ESC15 — Schema V1 template with enrollee-supplied subject (EKUwu / CVE-2024-49019)',
    summary: 'A version-1 template that lets the requester supply the subject also lets the requester inject arbitrary application policies (e.g. client authentication), even if the template’s own EKUs would not allow it.',
    eventIds: '4886/4887 (request received/issued)',
    fix: 'Apply the May 2024 updates, republish the template at schema version 2+, clear the enrollee-supplies-subject flag, and require manager approval.'
  }
};

var ESC_TEMPLATE_IDS = ['ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC9', 'ESC13', 'ESC15'];
var ESC_CA_IDS = ['ESC6', 'ESC7', 'ESC16'];

// ---------------------------------------------------------------------------
// Derivation: build computed ESC edges from the raw graph.
// Called from getGraphIndex() with the index maps still being assembled, so it
// must not call getGraphIndex() itself (that would recurse).
// ---------------------------------------------------------------------------
function deriveEscalationEdges(ctx) {
  var nodes = ctx.nodes, byKind = ctx.edgesByKind;
  function kindEdges(k) { return byKind.get(k) || []; }

  // DNS-name -> Domain node id, for templates/CAs that only carry a domain name.
  var domainByName = new Map();
  nodes.forEach(function (node) {
    if (node.kind !== 'Domain') return;
    var norm = normalizedNodeFields(node);
    if (norm.domain) domainByName.set(norm.domain, node.id);
    var name = norm.properties.name;
    if (name) domainByName.set(String(name).toUpperCase(), node.id);
  });
  function resolveDomainId(node) {
    if (!node) return null;
    var norm = normalizedNodeFields(node), props = norm.properties;
    var sid = props.domainsid;
    if (sid && nodes.has(String(sid))) return String(sid);
    if (norm.domain && domainByName.has(norm.domain)) return domainByName.get(norm.domain);
    return null;
  }

  // template id -> [PublishedTo edges]
  var pubByTemplate = new Map();
  kindEdges('publishedto').forEach(function (edge) {
    var tpl = nodes.get(edge.from);
    if (!tpl || tpl.kind !== 'CertTemplate') return;
    if (!pubByTemplate.has(edge.from)) pubByTemplate.set(edge.from, []);
    pubByTemplate.get(edge.from).push(edge);
  });

  function edgesByTarget(kinds) {
    var map = new Map();
    kinds.forEach(function (k) {
      kindEdges(k).forEach(function (edge) {
        if (!map.has(edge.to)) map.set(edge.to, []);
        // De-duplicate when a principal holds several enroll-granting rights.
        if (map.get(edge.to).indexOf(edge) === -1) map.get(edge.to).push(edge);
      });
    });
    return map;
  }
  var enrollByTarget = edgesByTarget(ESC_ENROLL_RIGHTS);
  var controlByTarget = edgesByTarget(ESC_TEMPLATE_CONTROL_RIGHTS);

  // issuance policy id -> group id, and template id -> [ExtendedByPolicy edges]
  var policyGroup = new Map(), policyLinkEdge = new Map();
  kindEdges('oidgrouplink').forEach(function (edge) {
    policyGroup.set(edge.from, edge.to);
    policyLinkEdge.set(edge.from, edge);
  });
  var policiesByTemplate = new Map();
  kindEdges('extendedbypolicy').forEach(function (edge) {
    var tpl = nodes.get(edge.from);
    if (!tpl || tpl.kind !== 'CertTemplate') return;
    if (!policiesByTemplate.has(edge.from)) policiesByTemplate.set(edge.from, []);
    policiesByTemplate.get(edge.from).push(edge);
  });

  var emitted = new Set();
  function emit(fromId, toId, escId, evidence, inherited) {
    if (!fromId || !toId) return;
    var kind = escKind(escId), key = fromId + '\u0000' + toId + '\u0000' + kind;
    if (emitted.has(key)) return;
    emitted.add(key);
    ctx.pushEdge({
      from: fromId, to: toId, kind: kind, category: 'adcs',
      computed: true, computedBy: 'viewer', esc: escId, inherited: !!inherited,
      evidenceEdges: evidence.filter(Boolean)
    });
  }

  // Template-scoped ESCs (ESC1/2/3/4/9/13/15).
  nodes.forEach(function (template) {
    if (template.kind !== 'CertTemplate') return;
    var pubs = pubByTemplate.get(template.id) || [];
    if (!pubs.length) return; // without publication there is no issuance path
    var flags = escTemplateFlags(template);
    if (!flags.enabled) return;
    var enrolls = enrollByTarget.get(template.id) || [];
    var domainId = resolveDomainId(template);

    if (domainId && enrolls.length) {
      ['ESC1', 'ESC2', 'ESC3', 'ESC9', 'ESC15'].forEach(function (escId) {
        if (!ESC_TEMPLATE_CONDITION[escId](flags)) return;
        enrolls.forEach(function (enroll) {
          emit(enroll.from, domainId, escId, [enroll].concat(pubs), enroll.inherited);
        });
      });
    }

    // ESC4: writable template -> reshape into ESC1, then enroll.
    var controls = controlByTarget.get(template.id) || [];
    if (domainId && controls.length) {
      controls.forEach(function (control) {
        emit(control.from, domainId, 'ESC4', [control].concat(pubs), control.inherited);
      });
    }

    // ESC13: enrolling grants membership in the policy-linked group.
    if (enrolls.length && ESC_TEMPLATE_CONDITION.ESC13(flags)) {
      (policiesByTemplate.get(template.id) || []).forEach(function (policyEdge) {
        var groupId = policyGroup.get(policyEdge.to);
        if (!groupId) return;
        enrolls.forEach(function (enroll) {
          emit(enroll.from, groupId, 'ESC13', [enroll, policyEdge, policyLinkEdge.get(policyEdge.to)].concat(pubs), enroll.inherited);
        });
      });
    }
  });

  // ESC6: a CA that accepts a requester-supplied SAN turns every enrollable
  // authentication template published to it into an ESC1-style path.
  nodes.forEach(function (ca) {
    if (ca.kind !== 'EnterpriseCA') return;
    if (!escCaFlags(ca).userSpecifiesSan) return;
    var caDomainId = resolveDomainId(ca);
    pubByTemplate.forEach(function (pubs, templateId) {
      var onThisCa = pubs.filter(function (edge) { return edge.to === ca.id; });
      if (!onThisCa.length) return;
      var template = nodes.get(templateId), flags = escTemplateFlags(template);
      if (!flags.enabled || !flags.authenticationEnabled || flags.requiresManagerApproval || flags.authorizedSignatures > 0) return;
      var domainId = caDomainId || resolveDomainId(template);
      if (!domainId) return;
      (enrollByTarget.get(templateId) || []).forEach(function (enroll) {
        emit(enroll.from, domainId, 'ESC6', [enroll].concat(onThisCa), enroll.inherited);
      });
    });
  });

  // ESC16: a CA that disables the SID security extension globally makes every
  // enrollable authentication template published to it an ESC9-style path.
  nodes.forEach(function (ca) {
    if (ca.kind !== 'EnterpriseCA') return;
    if (!escCaFlags(ca).securityExtensionDisabled) return;
    var caDomainId = resolveDomainId(ca);
    pubByTemplate.forEach(function (pubs, templateId) {
      var onThisCa = pubs.filter(function (edge) { return edge.to === ca.id; });
      if (!onThisCa.length) return;
      var template = nodes.get(templateId), flags = escTemplateFlags(template);
      if (!flags.enabled || !flags.authenticationEnabled || flags.requiresManagerApproval || flags.authorizedSignatures > 0) return;
      var domainId = caDomainId || resolveDomainId(template);
      if (!domainId) return;
      (enrollByTarget.get(templateId) || []).forEach(function (enroll) {
        emit(enroll.from, domainId, 'ESC16', [enroll].concat(onThisCa), enroll.inherited);
      });
    });
  });

  // ESC7: a principal that can administer or take over an enterprise CA can
  // issue or forge authentication certificates for any account. ManageCA (grant
  // yourself ManageCertificates, then approve) and ManageCertificates (approve a
  // held request) are the direct primitives; full control of the CA object lets
  // you grant yourself those rights. Modelled as a computed step to the domain.
  ESC7_CA_CONTROL_RIGHTS.forEach(function (right) {
    kindEdges(right).forEach(function (edge) {
      var ca = nodes.get(edge.to);
      if (!ca || ca.kind !== 'EnterpriseCA') return;
      var domainId = resolveDomainId(ca);
      if (!domainId || edge.from === domainId) return;
      emit(edge.from, domainId, 'ESC7', [edge], edge.inherited);
    });
  });
}

// ---------------------------------------------------------------------------
// Inspector helpers (run after the index is built, so getGraphIndex() is safe).
// ---------------------------------------------------------------------------
function escIsEnrollRight(kind) {
  return ESC_ENROLL_RIGHTS.indexOf(String(kind || '').toLowerCase()) !== -1;
}

// Expand a group id to every nested member (users, computers, groups).
function escNestedMembers(groupId) {
  var membersByGroup = getGraphIndex().membersByGroup;
  var out = [], seen = new Set(), queue = [groupId], qi = 0;
  while (qi < queue.length) {
    (membersByGroup.get(queue[qi++]) || []).forEach(function (id) {
      if (seen.has(id)) return;
      seen.add(id); out.push(id); queue.push(id);
    });
  }
  return out;
}

// Item 3: who can effectively enroll in a template — template enroll ACLs, CA
// enroll ACLs on every CA it is published to, and nested group membership,
// combined into a single principal list.
function escEffectiveEnrollers(template) {
  var index = getGraphIndex();
  var result = new Map(); // principalId -> {direct:[sources], viaGroups:Set}
  function ensure(id) {
    if (!result.has(id)) result.set(id, { direct: [], viaGroups: new Set() });
    return result.get(id);
  }
  function collect(targetId, sourceLabel) {
    (index.incoming.get(targetId) || []).forEach(function (edge) {
      if (!escIsEnrollRight(edge.kind)) return;
      var entry = ensure(edge.from);
      if (entry.direct.indexOf(sourceLabel) === -1) entry.direct.push(sourceLabel);
      var node = graph.nodes.get(edge.from);
      if (node && node.kind === 'Group') {
        escNestedMembers(edge.from).forEach(function (memberId) {
          if (memberId === edge.from) return;
          ensure(memberId).viaGroups.add(edge.from);
        });
      }
    });
  }
  collect(template.id, 'template');
  (index.edgesByKind.get('publishedto') || []).forEach(function (edge) {
    if (edge.from === template.id) collect(edge.to, 'CA');
  });
  return result;
}

// Evaluate the ESC conditions relevant to a selected template or CA and report
// each as met (vulnerable) or not met, with publication/enrollment context.
function escNodeChecks(node) {
  if (!node) return [];
  var checks = [];
  if (node.kind === 'CertTemplate') {
    var flags = escTemplateFlags(node), index = getGraphIndex();
    var published = (index.edgesByKind.get('publishedto') || []).some(function (edge) { return edge.from === node.id; });
    var enrollers = escEffectiveEnrollers(node);
    var policyLinked = (index.edgesByKind.get('extendedbypolicy') || []).some(function (edge) {
      if (edge.from !== node.id) return false;
      return (index.edgesByKind.get('oidgrouplink') || []).some(function (link) { return link.from === edge.to; });
    });
    ESC_TEMPLATE_IDS.forEach(function (escId) {
      var met;
      if (escId === 'ESC4') {
        met = (index.incoming.get(node.id) || []).some(function (edge) {
          return ESC_TEMPLATE_CONTROL_RIGHTS.indexOf(String(edge.kind || '').toLowerCase()) !== -1;
        });
      } else if (escId === 'ESC13') {
        met = ESC_TEMPLATE_CONDITION.ESC13(flags) && policyLinked;
      } else {
        met = ESC_TEMPLATE_CONDITION[escId](flags);
      }
      checks.push({ id: escId, def: ESC_DEFINITIONS[escId], met: met, published: published, enrollerCount: enrollers.size });
    });
  } else if (node.kind === 'EnterpriseCA') {
    var caFlags = escCaFlags(node);
    checks.push({ id: 'ESC6', def: ESC_DEFINITIONS.ESC6, met: caFlags.userSpecifiesSan, published: true, enrollerCount: null });
    var caIndex = getGraphIndex();
    var esc7Met = (caIndex.incoming.get(node.id) || []).some(function (edge) {
      return ESC7_CA_CONTROL_RIGHTS.indexOf(String(edge.kind || '').toLowerCase()) !== -1;
    });
    checks.push({ id: 'ESC7', def: ESC_DEFINITIONS.ESC7, met: esc7Met, published: true, enrollerCount: null });
    checks.push({ id: 'ESC16', def: ESC_DEFINITIONS.ESC16, met: caFlags.securityExtensionDisabled, published: true, enrollerCount: null });
  }
  return checks;
}

// Item 2: the AD CS settings that matter for a review.
function escSettingsRows(node) {
  var rows = [];
  if (node.kind === 'CertTemplate') {
    var f = escTemplateFlags(node);
    rows.push(['Authentication EKU', f.authenticationEnabled ? 'yes (logon-capable)' : 'no']);
    rows.push(['Subject name supplied by', f.enrolleeSuppliesSubject ? 'requester (ENROLLEE_SUPPLIES_SUBJECT)' : 'Active Directory']);
    rows.push(['Manager approval', f.requiresManagerApproval ? 'required' : 'not required']);
    rows.push(['Authorized signatures', String(f.authorizedSignatures)]);
    rows.push(['Schema version', f.schemaVersion == null ? '(unknown)' : String(f.schemaVersion)]);
    rows.push(['SID security extension', f.noSecurityExtension ? 'omitted (NO_SECURITY_EXTENSION)' : 'present']);
    rows.push(['EKUs / application policies', f.ekus.length ? f.ekus.join(', ') : '(none collected)']);
  } else if (node.kind === 'EnterpriseCA') {
    var c = escCaFlags(node);
    rows.push(['Requester may supply SAN', c.userSpecifiesSan ? 'yes (EDITF_ATTRIBUTESUBJECTALTNAME2)' : 'no']);
    rows.push(['Role separation', c.roleSeparation ? 'enabled' : 'not enabled']);
    rows.push(['Enrollment agent restrictions', c.hasEnrollmentAgentRestrictions ? 'present' : 'none']);
    rows.push(['SID security extension', c.securityExtensionDisabled ? 'disabled CA-wide (DisableExtensionList)' : 'enabled']);
    rows.push(['Web enrollment endpoints', c.webEnrollmentEndpoints.length ? c.webEnrollmentEndpoints.join(', ') : '(none collected)']);
  }
  return rows;
}

function escEnrollerListHtml(template) {
  var enrollers = escEffectiveEnrollers(template);
  if (!enrollers.size) {
    return '<div class="queryInfoText">No enrollment rights were collected for this template or its CAs.</div>';
  }
  var items = [];
  enrollers.forEach(function (entry, id) {
    var node = graph.nodes.get(id);
    var name = node ? displayName(node) : id;
    var kind = node ? node.kind : 'Unknown';
    var how = [];
    if (entry.direct.length) how.push('direct ' + entry.direct.join(' + ') + ' enroll right');
    if (entry.viaGroups.size) {
      var groups = [];
      entry.viaGroups.forEach(function (gid) { var g = graph.nodes.get(gid); groups.push(g ? displayName(g) : gid); });
      how.push('via ' + groups.join(', '));
    }
    items.push({ name: name, kind: kind, how: how.join('; '), direct: entry.direct.length > 0 });
  });
  items.sort(function (a, b) {
    return (a.direct === b.direct ? 0 : (a.direct ? -1 : 1)) || a.name.localeCompare(b.name);
  });
  var shown = items.slice(0, 50);
  return '<div class="adcsEnrollList">' + shown.map(function (item) {
    return '<div class="adcsEnrollRow"><span class="adcsEnrollName">' + escapeHtml(item.name) +
      '</span><span class="adcsEnrollKind">' + escapeHtml(item.kind) + '</span>' +
      '<span class="adcsEnrollHow">' + escapeHtml(item.how) + '</span></div>';
  }).join('') + '</div>' +
    (items.length > shown.length ? '<div class="queryInfoText">Showing ' + shown.length + ' of ' + items.length + ' effective enrollers.</div>' : '') +
    '<div class="adcsEnrollTotal">' + items.length + ' principal' + (items.length === 1 ? '' : 's') + ' can effectively enroll.</div>';
}

// The full AD CS Inspector section (items 2, 3, 4). Returns '' for non-AD CS
// nodes so selectNode() can concatenate it unconditionally.
function adcsInspectorHtml(node) {
  if (!node || (node.kind !== 'CertTemplate' && node.kind !== 'EnterpriseCA')) return '';
  var checks = escNodeChecks(node);
  var settings = escSettingsRows(node);

  var settingsHtml = '<table class="adcsSettingTable">' + settings.map(function (row) {
    return '<tr><td class="adcsSettingKey">' + escapeHtml(row[0]) + '</td><td class="adcsSettingVal">' + escapeHtml(row[1]) + '</td></tr>';
  }).join('') + '</table>';

  var checksHtml = checks.map(function (check) {
    var statusClass = check.met ? 'adcsCheckFail' : 'adcsCheckPass';
    var statusText = check.met ? 'VULNERABLE' : 'not met';
    var context = '';
    if (check.met && check.published === false) context = ' (template not published to a CA — no issuance path yet)';
    else if (check.met && check.enrollerCount === 0) context = ' (no enrollment rights collected yet)';
    var detail = '<div class="adcsCheckDetail">' + escapeHtml(check.def.summary) + '</div>';
    var defense = check.met
      ? '<div class="adcsDefense">' +
          '<div><span class="adcsDefenseLabel">Why it matters</span> ' + escapeHtml(check.def.summary) + '</div>' +
          '<div><span class="adcsDefenseLabel">Detection (Windows event IDs)</span> ' + escapeHtml(check.def.eventIds) + '</div>' +
          '<div><span class="adcsDefenseLabel">Remediation</span> ' + escapeHtml(check.def.fix) + '</div>' +
        '</div>'
      : '';
    return '<div class="adcsCheck ' + statusClass + '">' +
      '<div class="adcsCheckHead"><span class="adcsCheckMark">' + (check.met ? '✗' : '✓') + '</span>' +
      '<span class="adcsCheckTitle">' + escapeHtml(check.def.title) + '</span>' +
      '<span class="adcsCheckStatus">' + statusText + escapeHtml(context) + '</span></div>' +
      detail + defense + '</div>';
  }).join('');

  var html = '<div class="adcsSummary"><div class="adcsSummaryHead">AD CS review</div>' +
    '<div class="queryInfoSection"><div class="queryInfoLabel">Settings that matter</div>' + settingsHtml + '</div>' +
    '<div class="queryInfoSection"><div class="queryInfoLabel">ESC conditions (pass / fail)</div>' + checksHtml + '</div>';

  if (node.kind === 'CertTemplate') {
    html += '<div class="queryInfoSection"><div class="queryInfoLabel">Who can effectively enroll</div>' +
      escEnrollerListHtml(node) + '</div>';
  }
  html += '<div class="adcsSummaryNote">Computed from collected template/CA settings and enrollment ACLs. Validate publication, effective rights, and CA configuration before treating a condition as exploitable.</div></div>';
  return html;
}
