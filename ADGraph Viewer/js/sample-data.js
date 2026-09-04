// Extracted from NewOne/adCodex-cyberpunk.html; kept as a classic browser script.

// ---------------------------------------------------------------------------
// Sample data - small, and covers every relationship kind the parser handles.
// ---------------------------------------------------------------------------
var SAMPLE_FILES = (function () {
  var DOMAIN_SID = 'S-1-5-21-1111111111-2222222222-3333333333';
  function sid(rid) { return DOMAIN_SID + '-' + rid; }
  return [
    { filename: 'domains.json', json: { meta:{type:'domains',count:1,version:5}, data:[
      { ObjectIdentifier: DOMAIN_SID,
        Properties:{ name:'CORP.LOCAL', domain:'CORP.LOCAL', domainsid:DOMAIN_SID, highvalue:false },
        Aces:[{ PrincipalSID:sid(1601), PrincipalType:'Group', RightName:'GetChanges', IsInherited:false },
              { PrincipalSID:sid(1601), PrincipalType:'Group', RightName:'GetChangesAll', IsInherited:false }],
        ChildObjects:[{ ObjectIdentifier:sid(2001), ObjectType:'OU' }], Links:[],
        Trusts:[{ TargetDomainSid:'S-1-5-21-9999999999-8888888888-7777777777', TargetDomainName:'PARTNER.LOCAL',
                   TrustDirection:'Bidirectional', TrustType:'External', IsTransitive:true }]
      }
    ]}},
    { filename: 'ous.json', json: { meta:{type:'ous',count:1,version:5}, data:[
      { ObjectIdentifier: sid(2001), Properties:{ name:'WORKSTATIONS OU@CORP.LOCAL', domain:'CORP.LOCAL' }, Aces:[],
        ChildObjects:[{ ObjectIdentifier:sid(1201), ObjectType:'Computer' }],
        Links:[{ GUID:sid(3001), IsEnforced:false }] }
    ]}},
    { filename: 'gpos.json', json: { meta:{type:'gpos',count:1,version:5}, data:[
      { ObjectIdentifier: sid(3001), Properties:{ name:'DEFAULT DOMAIN POLICY@CORP.LOCAL', domain:'CORP.LOCAL' }, Aces:[] }
    ]}},
    { filename: 'users.json', json: { meta:{type:'users',count:3,version:5}, data:[
      { ObjectIdentifier: sid(1104), PrimaryGroupSID: sid(513),
        Properties:{ name:'JDOE@CORP.LOCAL', domain:'CORP.LOCAL', enabled:true, admincount:false, highvalue:false },
        Aces:[], SPNTargets:[] },
      { ObjectIdentifier: sid(1105), PrimaryGroupSID: sid(513),
        Properties:{ name:'ASMITH@CORP.LOCAL', domain:'CORP.LOCAL', enabled:true, admincount:true, highvalue:false },
        Aces:[], SPNTargets:[] },
      { ObjectIdentifier: sid(1106), PrimaryGroupSID: sid(513),
        Properties:{ name:'SVC_SQL@CORP.LOCAL', domain:'CORP.LOCAL', enabled:true, admincount:false, highvalue:false, hasspn:true },
        Aces:[], SPNTargets:[{ ComputerSID:sid(1301), Port:1433, Service:'MSSQLSvc' }] }
    ]}},
    { filename: 'groups.json', json: { meta:{type:'groups',count:5,version:5}, data:[
      { ObjectIdentifier: sid(512), Properties:{ name:'DOMAIN ADMINS@CORP.LOCAL', domain:'CORP.LOCAL', highvalue:true },
        Aces:[], Members:[{ ObjectIdentifier:sid(1105), ObjectType:'User' }] },
      { ObjectIdentifier: sid(1601), Properties:{ name:'HELP DESK@CORP.LOCAL', domain:'CORP.LOCAL', highvalue:false },
        Aces:[], Members:[{ ObjectIdentifier:sid(1104), ObjectType:'User' }] },
      { ObjectIdentifier: sid(513), Properties:{ name:'DOMAIN USERS@CORP.LOCAL', domain:'CORP.LOCAL', highvalue:false },
        Aces:[], Members:[] },
      { ObjectIdentifier: sid(515), Properties:{ name:'DOMAIN COMPUTERS@CORP.LOCAL', domain:'CORP.LOCAL', highvalue:false },
        Aces:[], Members:[{ ObjectIdentifier:sid(1201), ObjectType:'Computer' },{ ObjectIdentifier:sid(1301), ObjectType:'Computer' }] },
      { ObjectIdentifier: sid(516), Properties:{ name:'DOMAIN CONTROLLERS@CORP.LOCAL', domain:'CORP.LOCAL', highvalue:true },
        Aces:[], Members:[{ ObjectIdentifier:sid(1401), ObjectType:'Computer' }] }
    ]}},
    { filename: 'computers.json', json: { meta:{type:'computers',count:3,version:5}, data:[
      { ObjectIdentifier: sid(1201), PrimaryGroupSID: sid(515),
        Properties:{ name:'WORKSTATION01.CORP.LOCAL', domain:'CORP.LOCAL', operatingsystem:'Windows 11 Enterprise', enabled:true },
        Aces:[{ PrincipalSID:sid(1601), PrincipalType:'Group', RightName:'GenericAll', IsInherited:false }],
        Sessions:{ Results:[{ UserSID:sid(1105), ComputerSID:sid(1201) }], Collected:true },
        LocalAdmins:{ Results:[{ ObjectIdentifier:sid(1601), ObjectType:'Group' }], Collected:true },
        RemoteDesktopUsers:{ Results:[{ ObjectIdentifier:sid(1104), ObjectType:'User' }], Collected:true },
        DcomUsers:{ Results:[], Collected:true }, PSRemoteUsers:{ Results:[], Collected:true } },
      { ObjectIdentifier: sid(1301), PrimaryGroupSID: sid(515),
        Properties:{ name:'SQLSRV01.CORP.LOCAL', domain:'CORP.LOCAL', operatingsystem:'Windows Server 2022', enabled:true, unconstraineddelegation:true },
        Aces:[], Sessions:{ Results:[], Collected:true },
        LocalAdmins:{ Results:[{ ObjectIdentifier:sid(1105), ObjectType:'User' }], Collected:true },
        RemoteDesktopUsers:{ Results:[], Collected:true },
        DcomUsers:{ Results:[], Collected:true }, PSRemoteUsers:{ Results:[], Collected:true } },
      { ObjectIdentifier: sid(1401), PrimaryGroupSID: sid(516),
        Properties:{ name:'DC01.CORP.LOCAL', domain:'CORP.LOCAL', operatingsystem:'Windows Server 2022', enabled:true, highvalue:true },
        Aces:[], Sessions:{ Results:[], Collected:true }, LocalAdmins:{ Results:[], Collected:true },
        RemoteDesktopUsers:{ Results:[], Collected:true }, DcomUsers:{ Results:[], Collected:true }, PSRemoteUsers:{ Results:[], Collected:true } }
    ]}},
    { filename: 'certtemplates.json', json: { meta:{type:'certtemplates',count:1,version:6}, data:[
      { ObjectIdentifier:'CT-ESC1-DEMO',
        Properties:{ name:'USER AUTH ESC1@CORP.LOCAL', domain:'CORP.LOCAL', displayname:'User Auth ESC1',
          enrolleesuppliessubject:true, authenticationenabled:true, requiresmanagerapproval:false,
          authorizedsignatures:0, highvalue:true },
        Aces:[{ PrincipalSID:sid(1601), PrincipalType:'Group', RightName:'Enroll', IsInherited:false }] }
    ]}},
    { filename: 'enterprisecas.json', json: { meta:{type:'enterprisecas',count:1,version:6}, data:[
      { ObjectIdentifier:'CA-CORP-DEMO',
        Properties:{ name:'CORP-CA@CORP.LOCAL', domain:'CORP.LOCAL', caname:'CORP-CA', dnshostname:'DC01.CORP.LOCAL', highvalue:true },
        Aces:[], HostingComputer:{ ObjectIdentifier:sid(1401), ObjectType:'Computer' },
        EnabledCertTemplates:[{ ObjectIdentifier:'CT-ESC1-DEMO', ObjectType:'CertTemplate' }],
        CARegistryData:{ CASecurity:{ Results:[
          { PrincipalSID:sid(512), PrincipalType:'Group', RightName:'ManageCA', IsInherited:false }
        ]}}
      }
    ]}}
  ];
})();
