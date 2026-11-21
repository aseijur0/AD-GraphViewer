// Standalone AD CS misconfiguration sample (kept separate from the main
// SAMPLE_FILES on purpose — not wired into index.html yet, so it can be merged
// into js/sample-data.js later if wanted, or exported to disk and drag-dropped
// into the viewer as ordinary BloodHound JSON).
//
// It lives in its own domain (ADCSLAB.LOCAL) so it is coherent whether loaded
// on its own or alongside the CORP.LOCAL sample. The data is built to light up
// the AD CS review: it carries the relationships and settings that reveal the
// common escalation conditions (ESC1-4, ESC6-9, ESC13, ESC15) plus the PKI
// trust edges (HostsCAService, IssuedSignedBy, TrustedForNTAuth, *For domain).
//
// To merge later: concatenate ADCS_SAMPLE_FILES into SAMPLE_FILES, or load it
// in app.js the same way loadSampleData() consumes SAMPLE_FILES.
var ADCS_SAMPLE_FILES = (function () {
  var DOMAIN_SID = 'S-1-5-21-3300330033-4400440044-5500550055';
  function sid(rid) { return DOMAIN_SID + '-' + rid; }

  // Misconfiguration summary (for whoever reads this file):
  //  CT-ESC1          enrollee supplies subject on an auth template, no approval
  //  CT-ESC2          Any Purpose EKU
  //  CT-ESC3-AGENT    Certificate Request Agent EKU (enrollment agent)
  //  CT-ESC3-TARGET   requires an enrollment-agent signature (on-behalf target)
  //  CT-ESC4          writable template DACL (HELPDESK can rewrite it)
  //  CT-ESC9          no SID security extension
  //  CT-ESC13         issuance policy OID linked to a privileged group
  //  CT-ESC15         schema v1 + enrollee supplies subject (EKUwu)
  //  ADCSLAB-CA       requester-supplied SAN (ESC6), HTTP web enrollment (ESC8),
  //                   ManageCA/ManageCertificates + GenericAll to non-admins (ESC7)
  var CA_THUMB = 'A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1';
  var ROOT_THUMB = 'B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2';
  var ESC13_OID = '1.3.6.1.4.1.311.21.8.9999999';

  return [
    { filename: 'adcslab_domains.json', json: { meta:{type:'domains',count:1,version:6}, data:[
      { ObjectIdentifier: DOMAIN_SID,
        Properties:{ name:'ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, highvalue:false },
        Aces:[],
        ChildObjects:[
          { ObjectIdentifier:sid(1000), ObjectType:'Computer' },
          { ObjectIdentifier:sid(1100), ObjectType:'Computer' }
        ], Links:[], Trusts:[] }
    ]}},

    { filename: 'adcslab_groups.json', json: { meta:{type:'groups',count:6,version:6}, data:[
      { ObjectIdentifier: sid(512), Properties:{ name:'DOMAIN ADMINS@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:true },
        Aces:[], Members:[{ ObjectIdentifier:sid(1203), ObjectType:'User' }] },
      { ObjectIdentifier: sid(513), Properties:{ name:'DOMAIN USERS@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:false },
        Aces:[], Members:[] },
      { ObjectIdentifier: sid(515), Properties:{ name:'DOMAIN COMPUTERS@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:false },
        Aces:[], Members:[{ ObjectIdentifier:sid(1000), ObjectType:'Computer' },{ ObjectIdentifier:sid(1100), ObjectType:'Computer' }] },
      { ObjectIdentifier: sid(516), Properties:{ name:'DOMAIN CONTROLLERS@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:true },
        Aces:[], Members:[{ ObjectIdentifier:sid(1000), ObjectType:'Computer' }] },
      // Over-privileged help desk group: holds ManageCA + GenericAll on the CA
      // and WriteDacl on a template (ESC4 / ESC7 prerequisites).
      { ObjectIdentifier: sid(1301), Properties:{ name:'HELPDESK OPERATORS@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:false },
        Aces:[], Members:[{ ObjectIdentifier:sid(1202), ObjectType:'User' }] },
      // Privileged group reached purely by enrolling an ESC13 certificate.
      { ObjectIdentifier: sid(1302), Properties:{ name:'VULN OID GROUP@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', highvalue:true },
        Aces:[], Members:[] }
    ]}},

    { filename: 'adcslab_users.json', json: { meta:{type:'users',count:3,version:6}, data:[
      { ObjectIdentifier: sid(1201), PrimaryGroupSID: sid(513),
        Properties:{ name:'ALICE@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', enabled:true, highvalue:false },
        Aces:[], SPNTargets:[] },
      { ObjectIdentifier: sid(1202), PrimaryGroupSID: sid(513),
        Properties:{ name:'BOB_AGENT@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', enabled:true, highvalue:false },
        Aces:[], SPNTargets:[] },
      { ObjectIdentifier: sid(1203), PrimaryGroupSID: sid(513),
        Properties:{ name:'CAROL_PKIADMIN@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', enabled:true, highvalue:false },
        Aces:[], SPNTargets:[] }
    ]}},

    { filename: 'adcslab_computers.json', json: { meta:{type:'computers',count:2,version:6}, data:[
      { ObjectIdentifier: sid(1000), PrimaryGroupSID: sid(516),
        Properties:{ name:'DC01.ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', operatingsystem:'Windows Server 2022', enabled:true, highvalue:true },
        Aces:[], Sessions:{ Results:[], Collected:true }, LocalAdmins:{ Results:[], Collected:true },
        RemoteDesktopUsers:{ Results:[], Collected:true }, DcomUsers:{ Results:[], Collected:true }, PSRemoteUsers:{ Results:[], Collected:true } },
      { ObjectIdentifier: sid(1100), PrimaryGroupSID: sid(515),
        Properties:{ name:'PKI01.ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', operatingsystem:'Windows Server 2022', enabled:true },
        Aces:[], Sessions:{ Results:[], Collected:true }, LocalAdmins:{ Results:[], Collected:true },
        RemoteDesktopUsers:{ Results:[], Collected:true }, DcomUsers:{ Results:[], Collected:true }, PSRemoteUsers:{ Results:[], Collected:true } }
    ]}},

    { filename: 'adcslab_certtemplates.json', json: { meta:{type:'certtemplates',count:8,version:6}, data:[
      { ObjectIdentifier:'CT-ESC1-LAB',
        Properties:{ name:'LAB USER AUTH ESC1@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab User Auth ESC1',
          enrolleesuppliessubject:true, authenticationenabled:true, requiresmanagerapproval:false, authorizedsignatures:0,
          schemaversion:2, effectiveekus:['1.3.6.1.5.5.7.3.2'], highvalue:true },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] },
      { ObjectIdentifier:'CT-ESC2-LAB',
        Properties:{ name:'LAB ANY PURPOSE ESC2@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Any Purpose ESC2',
          enrolleesuppliessubject:false, requiresmanagerapproval:false, authorizedsignatures:0, schemaversion:2,
          effectiveekus:['2.5.29.37.0'] },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] },
      { ObjectIdentifier:'CT-ESC3-AGENT-LAB',
        Properties:{ name:'LAB ENROLLMENT AGENT ESC3@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Enrollment Agent ESC3',
          enrolleesuppliessubject:false, requiresmanagerapproval:false, authorizedsignatures:0, schemaversion:2,
          effectiveekus:['1.3.6.1.4.1.311.20.2.1'] },
        Aces:[{ PrincipalSID:sid(1202), PrincipalType:'User', RightName:'Enroll', IsInherited:false }],
        // Enrollment-agent -> on-behalf target relationship (ESC3 chain).
        Relationships:[{ Source:sid(1202), SourceType:'User', Target:'CT-ESC3-TARGET-LAB', TargetType:'CertTemplate', Kind:'EnrollOnBehalfOf' }] },
      { ObjectIdentifier:'CT-ESC3-TARGET-LAB',
        Properties:{ name:'LAB AGENT TARGET ESC3@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Agent Target ESC3',
          enrolleesuppliessubject:false, authenticationenabled:true, requiresmanagerapproval:false, authorizedsignatures:1, schemaversion:2,
          effectiveekus:['1.3.6.1.5.5.7.3.2'] },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] },
      { ObjectIdentifier:'CT-ESC4-LAB',
        Properties:{ name:'LAB WRITABLE TEMPLATE ESC4@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Writable Template ESC4',
          enrolleesuppliessubject:false, authenticationenabled:true, requiresmanagerapproval:true, authorizedsignatures:0, schemaversion:2 },
        Aces:[
          { PrincipalSID:sid(1301), PrincipalType:'Group', RightName:'WriteDacl', IsInherited:false },
          { PrincipalSID:sid(1301), PrincipalType:'Group', RightName:'WritePKIEnrollmentFlag', IsInherited:false },
          { PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }
        ] },
      { ObjectIdentifier:'CT-ESC9-LAB',
        Properties:{ name:'LAB NO SEC EXT ESC9@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab No Security Extension ESC9',
          enrolleesuppliessubject:false, authenticationenabled:true, requiresmanagerapproval:false, authorizedsignatures:0, schemaversion:2,
          nosecurityextension:true, effectiveekus:['1.3.6.1.5.5.7.3.2'] },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] },
      { ObjectIdentifier:'CT-ESC13-LAB',
        Properties:{ name:'LAB POLICY LINK ESC13@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Issuance Policy ESC13',
          enrolleesuppliessubject:false, requiresmanagerapproval:false, authorizedsignatures:0, schemaversion:2,
          certificatepolicy:[ESC13_OID] },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] },
      { ObjectIdentifier:'CT-ESC15-LAB',
        Properties:{ name:'LAB SCHEMA V1 ESC15@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, displayname:'Lab Schema V1 ESC15',
          enrolleesuppliessubject:true, authenticationenabled:false, requiresmanagerapproval:false, authorizedsignatures:0, schemaversion:1 },
        Aces:[{ PrincipalSID:sid(513), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] }
    ]}},

    { filename: 'adcslab_issuancepolicies.json', json: { meta:{type:'issuancepolicies',count:1,version:6}, data:[
      { ObjectIdentifier:'ISSUANCE-ESC13-LAB',
        Properties:{ name:'LAB PRIVILEGED ISSUANCE POLICY@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID,
          certtemplateoid:ESC13_OID },
        Aces:[], GroupLink:{ ObjectIdentifier:sid(1302), ObjectType:'Group' } }
    ]}},

    { filename: 'adcslab_rootcas.json', json: { meta:{type:'rootcas',count:1,version:6}, data:[
      { ObjectIdentifier:'ROOTCA-LAB',
        Properties:{ name:'ADCSLAB-ROOT-CA@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID,
          certthumbprint:ROOT_THUMB },
        Aces:[] }
    ]}},

    { filename: 'adcslab_ntauthstores.json', json: { meta:{type:'ntauthstores',count:1,version:6}, data:[
      { ObjectIdentifier:'NTAUTH-LAB',
        Properties:{ name:'NTAUTHCERTIFICATES@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID,
          certthumbprints:[CA_THUMB] },
        Aces:[] }
    ]}},

    { filename: 'adcslab_enterprisecas.json', json: { meta:{type:'enterprisecas',count:1,version:6}, data:[
      { ObjectIdentifier:'CA-ADCSLAB',
        Properties:{ name:'ADCSLAB-CA@ADCSLAB.LOCAL', domain:'ADCSLAB.LOCAL', domainsid:DOMAIN_SID, caname:'ADCSLAB-CA',
          dnshostname:'PKI01.ADCSLAB.LOCAL', certthumbprint:CA_THUMB, certchain:[CA_THUMB, ROOT_THUMB], highvalue:true },
        // Object DACL misconfiguration: help desk has full control of the CA (ESC7 / GoldenCert prerequisite).
        Aces:[{ PrincipalSID:sid(1301), PrincipalType:'Group', RightName:'GenericAll', IsInherited:false }],
        HostingComputer:{ ObjectIdentifier:sid(1100), ObjectType:'Computer' },
        // HTTP web enrollment endpoint without HTTPS/EPA -> ESC8 relay surface.
        WebEnrollmentEndpoints:['http://pki01.adcslab.local/certsrv/'],
        EnabledCertTemplates:[
          { ObjectIdentifier:'CT-ESC1-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC2-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC3-AGENT-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC3-TARGET-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC4-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC9-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC13-LAB', ObjectType:'CertTemplate' },
          { ObjectIdentifier:'CT-ESC15-LAB', ObjectType:'CertTemplate' }
        ],
        // Requester-supplied SAN (ESC6) and no enrollment-agent restrictions,
        // plus registry ACLs granting CA management to non-administrators (ESC7).
        CARegistryData:{
          IsUserSpecifiesSanEnabled:true,
          RoleSeparationEnabled:false,
          CASecurity:{ Results:[
            { PrincipalSID:sid(1301), PrincipalType:'Group', RightName:'ManageCA', IsInherited:false },
            { PrincipalSID:sid(1201), PrincipalType:'User', RightName:'ManageCertificates', IsInherited:false }
          ]}
        }
      }
    ]}}
  ];
})();

// Node exports for test harnesses / tooling; ignored in the browser.
if (typeof module !== 'undefined' && module.exports) { module.exports = { ADCS_SAMPLE_FILES: ADCS_SAMPLE_FILES }; }
