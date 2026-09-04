// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ============================================================================
// BloodHound-format JSON parser (DOM-free, testable in isolation)
// Schema confirmed against: bloodhound.specterops.io/integrations/bloodhound-api/json-formats
// and the SharpHound/BloodHound.py collector source (Aces, Properties, ObjectIdentifier,
// Sessions.Results, LocalAdmins.Results, Members, ChildObjects, Trusts, Links, etc.)
// ============================================================================

// A handful of well-known SIDs that are constant across every domain, so we can
// show a readable name instead of a raw SID when they show up as ACE principals
// or group members without ever appearing as a fully-collected object.
const WELL_KNOWN_SIDS = {
  'S-1-1-0': 'Everyone',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-18': 'SYSTEM',
  'S-1-5-19': 'LOCAL SERVICE',
  'S-1-5-20': 'NETWORK SERVICE',
  'S-1-2-0': 'LOCAL',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-32-544': 'BUILTIN\\Administrators',
  'S-1-5-32-545': 'BUILTIN\\Users',
  'S-1-5-32-546': 'BUILTIN\\Guests',
  'S-1-5-32-547': 'BUILTIN\\Power Users',
  'S-1-5-32-551': 'BUILTIN\\Backup Operators',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
};

const KNOWN_TYPES = ['computers', 'users', 'groups', 'domains', 'gpos', 'ous', 'containers',
  'certtemplates', 'enterprisecas', 'rootcas', 'aiacas', 'ntauthstores', 'issuancepolicies',
  'foreignsecurityprincipals'];

function makeGraph() {
  return { nodes: new Map(), edges: [], edgeKeys: new Set(), edgeByKey: new Map(), revision: 0 };
}

function normKind(rawType) {
  // meta.type / filename hints -> canonical singular kind used through the rest of the app
  const t = (rawType || '').toLowerCase().replace(/[^a-z]/g, '');
  if (t.startsWith('computer')) return 'Computer';
  if (t.startsWith('user')) return 'User';
  if (t.startsWith('group')) return 'Group';
  if (t.startsWith('domain')) return 'Domain';
  if (t.startsWith('gpo')) return 'GPO';
  if (t.startsWith('ou')) return 'OU';
  if (t.startsWith('container')) return 'Container';
  if (t.startsWith('certtemplate')) return 'CertTemplate';
  if (t.startsWith('enterpriseca')) return 'EnterpriseCA';
  if (t.startsWith('rootca')) return 'RootCA';
  if (t.startsWith('aiaca')) return 'AIACA';
  if (t.startsWith('ntauthstore')) return 'NTAuthStore';
  if (t.startsWith('issuancepolic')) return 'IssuancePolicy';
  if (t.startsWith('foreignsecurityprincipal') || t === 'fsp') return 'ForeignSecurityPrincipal';
  return null;
}

// ObjectType values found inside Members/Aces/LocalAdmins/ChildObjects entries use
// the same casing family as meta.type ("User", "Group", "Computer", ...) - normalize
// defensively since we've seen both "User" and "user" in the wild across collector versions.
function normObjectType(t) {
  // Unknown collector-specific labels must remain Unknown; inventing a kind
  // here creates nodes that are absent from KIND_ORDER and silently filtered.
  return normKind(t) || 'Unknown';
}

function ensureNode(graph, id, kind, seedProps) {
  if (!id) return null;
  id = String(id);
  const props = seedProps && typeof seedProps === 'object' && !Array.isArray(seedProps)
    ? seedProps : {};
  let n = graph.nodes.get(id);
  if (!n) {
    n = {
      id,
      kind: kind || 'Unknown',
      properties: props,
      isStub: true,
      highValue: false,
    };
    graph.nodes.set(id, n);
    graph.revision++;
  } else if (kind && (n.kind === 'Unknown' || !n.kind)) {
    n.kind = kind;
    graph.revision++;
  }
  if (n && n.isStub && Object.keys(props).length) {
    var changed = false, merged = Object.assign({}, n.properties || {});
    Object.keys(props).forEach(function (key) {
      if (merged[key] === undefined) { merged[key] = props[key]; changed = true; }
    });
    if (changed) { n.properties = merged; graph.revision++; }
  }
  return n;
}

function upsertFullNode(graph, id, kind, properties) {
  if (!id) return null;
  id = String(id);
  const props = properties && typeof properties === 'object' && !Array.isArray(properties)
    ? properties : {};
  let n = graph.nodes.get(id);
  const highValue = !!(props.highvalue || props.highValue || props.sensitive);
  if (!n) {
    n = { id, kind, properties: props, isStub: false, highValue };
    graph.nodes.set(id, n);
  } else {
    n.kind = kind;
    // BloodHound object types can be split across overlapping collections.
    // Preserve fields omitted by a partial record while allowing newer values
    // from the current upload to replace older values.
    n.properties = Object.assign({}, n.properties || {}, props);
    n.isStub = false;
    n.highValue = n.highValue || highValue;
  }
  graph.revision++;
  return n;
}

function displayName(node) {
  if (!node) return '(unknown)';
  const p = node.properties || {};
  return p.name || p.displayname || WELL_KNOWN_SIDS[node.id] || node.id;
}

function addEdge(graph, from, to, kind, category, extra) {
  if (!from || !to) return;
  const edge = {};
  if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
    for (const key of Object.keys(extra)) {
      // Collector-controlled relationship metadata must never replace graph
      // identity fields or mutate the new object's prototype.
      if (key === 'from' || key === 'to' || key === 'kind' || key === 'category' ||
          key === '__proto__' || key === 'prototype' || key === 'constructor') continue;
      edge[key] = extra[key];
    }
  }
  edge.from = String(from);
  edge.to = String(to);
  edge.kind = String(kind || 'Relationship');
  edge.category = String(category || 'other');
  var variantKey = edgeVariantKey(edge);
  if (!graph.edgeKeys || !graph.edgeByKey) {
    graph.edgeKeys = new Set(); graph.edgeByKey = new Map();
    graph.edges.forEach(function (existing) {
      var existingKey = edgeVariantKey(existing); graph.edgeKeys.add(existingKey); graph.edgeByKey.set(existingKey, existing);
    });
  }
  if (graph.edgeKeys.has(variantKey)) {
    var existingEdge = graph.edgeByKey.get(variantKey), changed = false;
    Object.keys(edge).forEach(function (key) {
      if (key === 'from' || key === 'to' || key === 'kind' || key === 'category') return;
      if (existingEdge[key] !== edge[key]) { existingEdge[key] = edge[key]; changed = true; }
    });
    if (changed) graph.revision++;
    return false;
  }
  graph.edgeKeys.add(variantKey);
  graph.edgeByKey.set(variantKey, edge);
  graph.edges.push(edge);
  graph.revision++;
  return true;
}

// ACEs are structurally identical across every object type, so this one function
// covers GenericAll/GenericWrite/WriteDacl/WriteOwner/Owns/ForceChangePassword/
// AllExtendedRights/AddMember/ReadLAPSPassword/ReadGMSAPassword/etc - we don't need
// to special-case each right name, we just use RightName as the edge kind.
function extractAces(graph, objId, aces) {
  if (!Array.isArray(aces)) return;
  for (const ace of aces) {
    if (!ace || !ace.PrincipalSID || ace.PrincipalSID === objId) continue;
    ensureNode(graph, ace.PrincipalSID, normObjectType(ace.PrincipalType));
    addEdge(graph, ace.PrincipalSID, objId, ace.RightName || 'ACE', 'acl', {
      inherited: !!ace.IsInherited,
    });
  }
}

function extractSIDHistory(graph, objId, values) {
  for (const value of resultsArray(values)) {
    const historicalId = typedPrincipalId(value);
    if (!historicalId || historicalId === objId) continue;
    ensureNode(graph, historicalId, typeof value === 'object' ? normObjectType(value.ObjectType) : 'Unknown');
    // The current principal carries the target SID and therefore inherits the
    // target principal's privileges. This is BloodHound's documented direction.
    addEdge(graph, objId, historicalId, 'HasSIDHistory', 'access');
  }
}

function resultsArray(field) {
  // Some collections (Sessions/LocalAdmins/RemoteDesktopUsers/...) wrap results as
  // {Results:[...], Collected, FailureReason}; a few community collectors emit a bare
  // array instead. Accept both so a slightly different collector doesn't silently break.
  if (!field) return [];
  if (Array.isArray(field)) return field;
  if (Array.isArray(field.Results)) return field.Results;
  return [];
}

function parseUsers(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    const node = upsertFullNode(graph, id, 'User', obj.Properties);
    extractAces(graph, id, obj.Aces);

    if (obj.PrimaryGroupSID) {
      ensureNode(graph, obj.PrimaryGroupSID, 'Group');
      addEdge(graph, id, obj.PrimaryGroupSID, 'MemberOf', 'structural');
    }
    for (const t of obj.AllowedToDelegate || []) {
      const targetId = typeof t === 'string' ? t : t?.ObjectIdentifier;
      if (!targetId) continue;
      ensureNode(graph, targetId, 'Computer');
      addEdge(graph, id, targetId, 'AllowedToDelegate', 'access');
    }
    extractSIDHistory(graph, id, obj.HasSIDHistory);
    for (const s of obj.SPNTargets || []) {
      const cid = s?.ComputerSID;
      if (!cid) continue;
      ensureNode(graph, cid, 'Computer');
      addEdge(graph, id, cid, 'SPNTarget', 'access');
    }
  }
}

function parseComputers(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    const node = upsertFullNode(graph, id, 'Computer', obj.Properties);
    extractAces(graph, id, obj.Aces);

    if (obj.PrimaryGroupSID) {
      ensureNode(graph, obj.PrimaryGroupSID, 'Group');
      addEdge(graph, id, obj.PrimaryGroupSID, 'MemberOf', 'structural');
    }
    for (const s of resultsArray(obj.Sessions)) {
      const uid = s?.UserSID;
      if (!uid) continue;
      ensureNode(graph, uid, 'User');
      addEdge(graph, id, uid, 'HasSession', 'access');
    }
    const localGroupMap = {
      LocalAdmins: 'AdminTo',
      RemoteDesktopUsers: 'CanRDP',
      DcomUsers: 'ExecuteDCOM',
      PSRemoteUsers: 'CanPSRemote',
    };
    for (const [field, edgeKind] of Object.entries(localGroupMap)) {
      for (const r of resultsArray(obj[field])) {
        const pid = r?.ObjectIdentifier;
        if (!pid) continue;
        ensureNode(graph, pid, normObjectType(r.ObjectType));
        addEdge(graph, pid, id, edgeKind, 'access');
      }
    }
    for (const a of obj.AllowedToAct || []) {
      const pid = typeof a === 'string' ? a : a?.ObjectIdentifier;
      if (!pid) continue;
      ensureNode(graph, pid, typeof a === 'object' ? normObjectType(a.ObjectType) : 'Unknown');
      addEdge(graph, pid, id, 'AllowedToAct', 'access');
    }
    for (const t of obj.AllowedToDelegate || []) {
      const targetId = typeof t === 'string' ? t : t?.ObjectIdentifier;
      if (!targetId) continue;
      ensureNode(graph, targetId, 'Computer');
      addEdge(graph, id, targetId, 'AllowedToDelegate', 'access');
    }
    extractSIDHistory(graph, id, obj.HasSIDHistory);
  }
}

function parseGroups(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'Group', obj.Properties);
    extractAces(graph, id, obj.Aces);
    extractSIDHistory(graph, id, obj.HasSIDHistory);
    for (const m of resultsArray(obj.Members)) {
      const mid = m?.ObjectIdentifier;
      if (!mid) continue;
      ensureNode(graph, mid, normObjectType(m.ObjectType));
      addEdge(graph, mid, id, 'MemberOf', 'structural');
    }
  }
}

function parseContainment(graph, id, obj) {
  for (const c of resultsArray(obj.ChildObjects)) {
    const cid = c?.ObjectIdentifier;
    if (!cid) continue;
    ensureNode(graph, cid, normObjectType(c.ObjectType));
    addEdge(graph, id, cid, 'Contains', 'structural');
  }
  for (const l of resultsArray(obj.Links)) {
    const gpoId = l?.GUID || l?.ObjectIdentifier;
    if (!gpoId) continue;
    ensureNode(graph, gpoId, 'GPO');
    addEdge(graph, gpoId, id, 'GPLink', 'structural', { enforced: !!l.IsEnforced });
  }
}

function parseDomains(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'Domain', obj.Properties);
    extractAces(graph, id, obj.Aces);
    parseContainment(graph, id, obj);
    for (const t of resultsArray(obj.Trusts)) {
      const targetId = t?.TargetDomainSid || t?.TargetDomainSID || t?.TargetDomainId || t?.TargetDomainID;
      if (!targetId) continue;
      ensureNode(graph, targetId, 'Domain', { name: t.TargetDomainName });
      const directionMap = { '0': 'disabled', '1': 'inbound', '2': 'outbound', '3': 'bidirectional' };
      const rawDirection = String(t.TrustDirection ?? '').toLowerCase();
      const direction = directionMap[rawDirection] || rawDirection;
      const trustMeta = {
        direction: t.TrustDirection,
        trustType: t.TrustType,
        transitive: !!t.IsTransitive,
        sidFilteringEnabled: t.SidFilteringEnabled ?? t.SIDFilteringEnabled,
        sidFilteringQuarantined: t.SidFilteringQuarantined ?? t.SIDFilteringQuarantined,
        targetDomainName: t.TargetDomainName,
      };
      const trustType = String(t.TrustType || '').toLowerCase();
      const edgeKind = /forest|external/.test(trustType) ? 'CrossForestTrust' :
        (/parent|child|intra|tree/.test(trustType) ? 'SameForestTrust' : 'Trust');
      // BloodHound trust edges point from the trusting domain to the trusted
      // domain. An inbound trust means this domain trusts the target; outbound
      // means the target trusts this domain.
      if (direction === 'inbound' || direction === 'bidirectional') {
        addEdge(graph, id, targetId, edgeKind, 'structural', trustMeta);
      }
      if (direction === 'outbound' || direction === 'bidirectional') {
        addEdge(graph, targetId, id, edgeKind, 'structural', trustMeta);
      }
    }
  }
}

function parseOUs(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'OU', obj.Properties);
    extractAces(graph, id, obj.Aces);
    parseContainment(graph, id, obj);
  }
}

function parseContainers(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'Container', obj.Properties);
    extractAces(graph, id, obj.Aces);
    parseContainment(graph, id, obj);
  }
}

function parseGPOs(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'GPO', obj.Properties);
    extractAces(graph, id, obj.Aces);
  }
}

function parseForeignSecurityPrincipals(graph, data) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier;
    if (!id) continue;
    upsertFullNode(graph, id, 'ForeignSecurityPrincipal', obj.Properties);
    extractAces(graph, id, obj.Aces);
    extractSIDHistory(graph, id, obj.HasSIDHistory);
  }
}

function typedPrincipalId(value) {
  if (!value) return null;
  if (typeof value === 'string') return value;
  return value.ObjectIdentifier || value.objectIdentifier || value.ObjectID || value.objectid || value.ID || value.id || null;
}

function addTypedReference(graph, from, to, kind, fromKind, toKind, extra) {
  if (!from || !to) return;
  ensureNode(graph, from, fromKind || 'Unknown');
  ensureNode(graph, to, toKind || 'Unknown');
  addEdge(graph, from, to, kind, 'adcs', extra);
}

function parsePKIObjects(graph, data, kind) {
  for (const obj of data) {
    const id = obj.ObjectIdentifier || obj.ObjectID || obj.objectid || obj.id;
    if (!id) continue;
    upsertFullNode(graph, id, kind, obj.Properties || obj.properties || {});
    extractAces(graph, id, obj.Aces || obj.aces);

    // Enterprise CA -> published template data is collected on the CA, while
    // BloodHound represents the graph edge in the useful Template -> CA direction.
    for (const template of resultsArray(obj.EnabledCertTemplates || obj.PublishedTemplates || obj.CertificateTemplates)) {
      const templateId = typedPrincipalId(template);
      addTypedReference(graph, templateId, id, 'PublishedTo', 'CertTemplate', 'EnterpriseCA');
    }
    for (const ca of resultsArray(obj.PublishedTo || obj.EnterpriseCAs)) {
      const caId = typedPrincipalId(ca);
      addTypedReference(graph, id, caId, 'PublishedTo', 'CertTemplate', 'EnterpriseCA');
    }

    const host = typedPrincipalId(obj.HostingComputer || obj.CAHost || obj.Computer);
    if (host) addTypedReference(graph, host, id, 'HostsCAService', 'Computer', 'EnterpriseCA');

    const group = typedPrincipalId(obj.GroupLink || obj.OIDGroupLink);
    if (group) addTypedReference(graph, id, group, 'OIDGroupLink', 'IssuancePolicy', 'Group');

    for (const policy of resultsArray(obj.IssuancePolicyObjects || obj.ExtendedByPolicy)) {
      const policyId = typedPrincipalId(policy);
      addTypedReference(graph, id, policyId, 'ExtendedByPolicy', 'CertTemplate', 'IssuancePolicy');
    }

    // CA registry ACLs carry ManageCA / ManageCertificates rights separately
    // from the LDAP object ACL. Collector versions use either CASecurity or
    // CARegistryData.CASecurity and may wrap the ACE array in Results/Data.
    const registry = obj.CARegistryData || obj.RegistryData || {};
    const caSecurity = registry.CASecurity || obj.CASecurity;
    const caAces = resultsArray(caSecurity && (caSecurity.Results || caSecurity.Data || caSecurity));
    for (const ace of caAces) {
      const principal = ace && (ace.PrincipalSID || ace.ObjectIdentifier);
      if (!principal || principal === id) continue;
      const right = ace.RightName || ace.Right || ace.AccessRight || 'ManageCA';
      addTypedReference(graph, principal, id, right, normObjectType(ace.PrincipalType || ace.ObjectType), 'EnterpriseCA', { inherited: !!ace.IsInherited });
    }

    // Accept relationships emitted by community/OpenGraph collectors without
    // tying ingestion to one producer's field casing.
    for (const rel of resultsArray(obj.Relationships || obj.Edges)) {
      const target = typedPrincipalId(rel.Target || rel.End || rel.To || rel);
      const source = typedPrincipalId(rel.Source || rel.Start || rel.From) || id;
      const edgeKind = rel.Kind || rel.Type || rel.RelationshipType;
      if (target && edgeKind) addTypedReference(graph, source, target, edgeKind,
        normObjectType(rel.SourceType), normObjectType(rel.TargetType), rel.Properties || {});
    }
  }
}

function parseCertTemplates(graph, data) { parsePKIObjects(graph, data, 'CertTemplate'); }
function parseEnterpriseCAs(graph, data) { parsePKIObjects(graph, data, 'EnterpriseCA'); }
function parseRootCAs(graph, data) { parsePKIObjects(graph, data, 'RootCA'); }
function parseAIACAs(graph, data) { parsePKIObjects(graph, data, 'AIACA'); }
function parseNTAuthStores(graph, data) { parsePKIObjects(graph, data, 'NTAuthStore'); }
function parseIssuancePolicies(graph, data) { parsePKIObjects(graph, data, 'IssuancePolicy'); }

function edgeIdentityKey(from, to, kind) {
  return JSON.stringify([String(from), String(to), String(kind)]);
}

function edgeVariantKey(edge) {
  return JSON.stringify([String(edge.from), String(edge.to), String(edge.kind), !!edge.inherited]);
}

function pathIdentityKey(nodeIds, edges) {
  return JSON.stringify([nodeIds, edges.map(edgeVariantKey)]);
}

function addEdgeOnce(graph, from, to, kind, category, extra, edgeKeys) {
  if (!from || !to) return;
  var key = edgeIdentityKey(from, to, kind);
  var exists = edgeKeys
    ? edgeKeys.has(key)
    : graph.edges.some(function (edge) {
        return edgeIdentityKey(edge.from, edge.to, edge.kind) === key;
      });
  if (exists) return;
  addEdge(graph, from, to, kind, category, extra);
  if (edgeKeys) edgeKeys.add(key);
}

function reconcileADCSRelationships(graph) {
  const byThumbprint = new Map();
  const policyByOID = new Map();
  // Reconciliation can add many derived PKI edges. Index existing identities
  // once instead of scanning the entire edge array for every candidate.
  const edgeKeys = new Set(graph.edges.map(function (edge) {
    return edgeIdentityKey(edge.from, edge.to, edge.kind);
  }));
  graph.nodes.forEach(function (node) {
    const props = node.properties || {};
    if (props.certthumbprint) byThumbprint.set(String(props.certthumbprint).toUpperCase(), node.id);
    if (node.kind === 'IssuancePolicy' && props.certtemplateoid) policyByOID.set(String(props.certtemplateoid), node.id);
  });

  graph.nodes.forEach(function (node) {
    const props = node.properties || {};
    const domainId = props.domainsid && graph.nodes.has(props.domainsid) ? props.domainsid : null;
    const forEdge = {
      EnterpriseCA: 'EnterpriseCAFor', RootCA: 'RootCAFor',
      AIACA: 'AIACAFor', NTAuthStore: 'NTAuthStoreFor'
    }[node.kind];
    if (forEdge && domainId) addEdgeOnce(graph, node.id, domainId, forEdge, 'adcs', null, edgeKeys);

    if ((node.kind === 'EnterpriseCA' || node.kind === 'AIACA' || node.kind === 'RootCA') && Array.isArray(props.certchain)) {
      const chainIds = props.certchain.map(function (thumbprint) {
        return byThumbprint.get(String(thumbprint).toUpperCase());
      }).filter(Boolean);
      if (chainIds.length && chainIds[0] !== node.id) chainIds.unshift(node.id);
      for (let i = 0; i + 1 < chainIds.length; i++) {
        addEdgeOnce(graph, chainIds[i], chainIds[i + 1], 'IssuedSignedBy', 'adcs', null, edgeKeys);
      }
    }

    if (node.kind === 'NTAuthStore' && Array.isArray(props.certthumbprints)) {
      props.certthumbprints.forEach(function (thumbprint) {
        const caId = byThumbprint.get(String(thumbprint).toUpperCase());
        if (caId) addEdgeOnce(graph, caId, node.id, 'TrustedForNTAuth', 'adcs', null, edgeKeys);
      });
    }

    if (node.kind === 'CertTemplate') {
      const oids = [].concat(props.certificatepolicy || props.certificatepolicies || []);
      oids.forEach(function (oid) {
        const policyId = policyByOID.get(String(oid));
        if (policyId) addEdgeOnce(graph, node.id, policyId, 'ExtendedByPolicy', 'adcs', null, edgeKeys);
      });
    }
  });
}

const PARSERS = {
  users: parseUsers,
  computers: parseComputers,
  groups: parseGroups,
  domains: parseDomains,
  ous: parseOUs,
  containers: parseContainers,
  gpos: parseGPOs,
  certtemplates: parseCertTemplates,
  enterprisecas: parseEnterpriseCAs,
  rootcas: parseRootCAs,
  aiacas: parseAIACAs,
  ntauthstores: parseNTAuthStores,
  issuancepolicies: parseIssuancePolicies,
  foreignsecurityprincipals: parseForeignSecurityPrincipals,
};

function detectType(json, filename) {
  const metaType = json && json.meta && (json.meta.type || json.meta.datatype);
  if (metaType && PARSERS[metaType.toLowerCase()]) return metaType.toLowerCase();

  const f = (filename || '').toLowerCase();
  for (const t of KNOWN_TYPES) {
    if (f.includes(t) || f.includes(t.slice(0, -1))) return t;
  }

  const first = json && Array.isArray(json.data) ? json.data[0] : null;
  if (first) {
    if ('EnabledCertTemplates' in first || 'HostingComputer' in first || 'CARegistryData' in first) return 'enterprisecas';
    if ((json.meta && /certtemplate/i.test(json.meta.type || json.meta.datatype || '')) || ('Properties' in first && first.Properties && ('enrolleesuppliessubject' in first.Properties || 'authenticationenabled' in first.Properties))) return 'certtemplates';
    if ('GroupLink' in first || 'OIDGroupLink' in first) return 'issuancepolicies';
    if ('Sessions' in first || 'LocalAdmins' in first) return 'computers';
    if ('Members' in first) return 'groups';
    if ('Trusts' in first) return 'domains';
    if ('Links' in first && 'ChildObjects' in first) return 'ous';
    if ('SPNTargets' in first) return 'users';
    if ('ChildObjects' in first) return 'domains';
    if ('Aces' in first) return 'gpos';
  }
  return null;
}

// Ingests one already-JSON.parsed BloodHound export file into the shared graph.
// Returns {type, count} for UI feedback, or {error} if the file couldn't be placed.
function ingestFile(graph, json, filename) {
  if (!json || !Array.isArray(json.data)) {
    return { error: `${filename}: not a recognizable BloodHound JSON file (missing "data" array)` };
  }
  const type = detectType(json, filename);
  if (!type || !PARSERS[type]) {
    return { error: `${filename}: could not determine object type (expected users/groups/computers/domains/gpos/ous/containers)` };
  }
  PARSERS[type](graph, json.data);
  return { type, count: json.data.length };
}
