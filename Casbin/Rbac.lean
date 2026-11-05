import Casbin.Management

namespace Casbin

def Enforcer.getUsersForRole (e : Enforcer) (role : String) (domain : Option String := none)
    (ptype : String := "g") : Except String (List String) := do
  let defn ← findDefinition e.model.roles ptype
  if (defn.fields.length == 3) != domain.isSome then throw "incorrect domain argument count"
  let roleRules := e.roleSnapshot.getD e.rules
  if let some (_, manager) := e.roleManagers.find? (·.1 == ptype) then
    return ← manager.getUsers (roleRules.filter (·.ptype == ptype)) role domain
  let mut result := []
  for rule in roleRules.filter (·.ptype == ptype) do
    let parent := rule.values[1]?.getD ""
    if parent != role then
      let some (_, fn) := e.roleMatchers.find? (·.1 == ptype) | continue
      if !(← fn role parent) then continue
    if let some dom := domain then
      let stored := rule.values[2]?.getD ""
      if dom != stored then
        let some (_, fn) := e.domainMatchers.find? (·.1 == ptype) | continue
        if !(← fn dom stored) then continue
    result := result ++ [rule.values[0]?.getD ""]
  return result.eraseDups

def Enforcer.hasRoleForUser (e : Enforcer) (user role : String) (domain : Option String := none) : Except String Bool :=
  (e.getRolesForUser user domain).map (·.contains role)

def Enforcer.addRoleForUser (e : Enforcer) (user role : String) (domain : Option String := none) :
    Except String (Enforcer × Bool) := e.addGroupingPolicy ([user, role] ++ domain.toList)

def Enforcer.addRolesForUser (e : Enforcer) (user : String) (roles : List String) (domain : Option String := none) :
    Except String (Enforcer × Bool) := e.addGroupingPolicies (roles.map fun role => [user, role] ++ domain.toList) "g" true

def Enforcer.deleteRoleForUser (e : Enforcer) (user role : String) (domain : Option String := none) :
    Except String (Enforcer × Bool) := e.removeGroupingPolicy ([user, role] ++ domain.toList)

def Enforcer.deleteRolesForUser (e : Enforcer) (user : String) (domain : Option String := none) :
    Except String (Enforcer × Bool) := e.removeFilteredGroupingPolicy 0 ([user, ""] ++ domain.toList)

private def setRules (e : Enforcer) (rules : List Rule) : Except String (Enforcer × Bool) := do
  validateConstraints e.model rules
  return ({ e with rules := rules }, rules != e.rules)

def Enforcer.deleteUser (e : Enforcer) (user : String) : Except String (Enforcer × Bool) :=
  setRules e (e.rules.filter fun rule =>
    if e.model.roles.any (·.name == rule.ptype) then rule.values[0]? != some user
    else if let .ok idx := e.getFieldIndex rule.ptype "sub" then rule.values[idx]? != some user
    else true)

def Enforcer.deleteRole (e : Enforcer) (role : String) : Except String (Enforcer × Bool) :=
  setRules e (e.rules.filter fun rule =>
    if e.model.roles.any (·.name == rule.ptype) then rule.values[0]? != some role && rule.values[1]? != some role
    else if let .ok idx := e.getFieldIndex rule.ptype "sub" then rule.values[idx]? != some role
    else true)

def Enforcer.getImplicitRolesForUser (e : Enforcer) (user : String) (domain : Option String := none)
    (ptype : String := "g") : Except String (List String) := do
  let mut seen := [user]
  let mut frontier := [user]
  let mut result := []
  for _ in [:e.rules.length + 1] do
    let mut next := []
    for name in frontier do
      for role in ← e.getRolesForUser name domain ptype do
        if !seen.contains role then
          seen := seen ++ [role]
          result := result ++ [role]
          next := next ++ [role]
    if next.isEmpty then break
    frontier := next
  return result

def Enforcer.getImplicitUsersForRole (e : Enforcer) (role : String) (domain : Option String := none)
    (ptype : String := "g") : Except String (List String) := do
  let candidates := ((e.getGroupingPolicy ptype).filterMap (·[0]?)).eraseDups
  let mut users := []
  for user in candidates do
    if user != role && (← e.hasLink user role domain ptype) then users := users ++ [user]
  return users

def Enforcer.getPermissionsForUser (e : Enforcer) (user : String) (domain : Option String := none)
    (ptype : String := "p") : Except String (List (List String)) := do
  let subIdx ← e.getFieldIndex ptype "sub"
  let domIdx := (e.getFieldIndex ptype "dom").toOption
  if domain.isSome && domIdx.isNone then throw "selected policy has no domain field"
  return (e.getPolicy ptype).filter fun row => row[subIdx]? == some user &&
    (domain.isNone || (domIdx.bind (row[·]?)) == domain)

def Enforcer.getImplicitPermissionsForUser (e : Enforcer) (user : String) (domain : Option String := none)
    (ptype : String := "p") (gtype : String := "g") : Except String (List (List String)) := do
  let roles ← e.getImplicitRolesForUser user domain gtype
  let idx ← e.getFieldIndex ptype "sub"
  let domIdx := (e.getFieldIndex ptype "dom").toOption
  if domain.isSome && domIdx.isNone then throw "selected policy has no domain field"
  let mut result := []
  for row in e.getPolicy ptype do
    if !(user :: roles).contains (row[idx]?.getD "") then continue
    if let some dom := domain then
      let i := domIdx.getD 0
      let policyDom := row[i]?.getD ""
      if dom != policyDom then
        let some (_, fn) := e.domainMatchers.find? (·.1 == gtype) | continue
        if !(← fn dom policyDom) then continue
      result := result ++ [row.set i dom]
    else result := result ++ [row]
  return result.eraseDups

def Enforcer.addPermissionForUser (e : Enforcer) (user : String) (permission : List String) :
    Except String (Enforcer × Bool) := e.addPolicy (user :: permission)
def Enforcer.addPermissionsForUser (e : Enforcer) (user : String) (permissions : List (List String)) :
    Except String (Enforcer × Bool) := e.addPolicies (permissions.map (user :: ·)) "p" true
def Enforcer.deletePermissionForUser (e : Enforcer) (user : String) (permission : List String) :
    Except String (Enforcer × Bool) := e.removePolicy (user :: permission)
def Enforcer.deletePermissionsForUser (e : Enforcer) (user : String) : Except String (Enforcer × Bool) := do
  let idx ← e.getFieldIndex "p" "sub"
  e.removeFilteredPolicy idx [user]
def Enforcer.deletePermission (e : Enforcer) (permission : List String) : Except String (Enforcer × Bool) :=
  e.removeFilteredPolicy 1 permission
def Enforcer.hasPermissionForUser (e : Enforcer) (user : String) (permission : List String) : Bool :=
  e.hasPolicy (user :: permission)

def Enforcer.getAllDomains (e : Enforcer) : List String :=
  (e.rules.filterMap fun rule =>
    if e.model.roles.any (fun role => role.name == rule.ptype && role.fields.length == 3) then rule.values[2]?
    else if let .ok idx := e.getFieldIndex rule.ptype "dom" then rule.values[idx]?
    else none).eraseDups

def Enforcer.getDomainsForUser (e : Enforcer) (user : String) : Except String (List String) := do
  let mut domains := []
  for domain in e.getAllDomains do
    if !(← e.getImplicitRolesForUser user (some domain)).isEmpty then domains := domains ++ [domain]
  return domains

def Enforcer.getAllRolesByDomain (e : Enforcer) (domain : String) : List String :=
  ((e.getGroupingPolicy).filter (fun row => row[2]? == some domain)).filterMap (·[1]?) |>.eraseDups

def Enforcer.getAllUsersByDomain (e : Enforcer) (domain : String) : List String :=
  let links := ((e.getGroupingPolicy).filter (fun row => row[2]? == some domain)).filterMap (·[0]?)
  let policies := match e.getFieldIndex "p" "dom", e.getFieldIndex "p" "sub" with
    | .ok dom, .ok sub => ((e.getPolicy).filter (fun row => row[dom]? == some domain)).filterMap (·[sub]?)
    | _, _ => []
  (links ++ policies).eraseDups

def Enforcer.deleteDomains (e : Enforcer) (domains : List String) : Except String (Enforcer × Bool) :=
  setRules e (e.rules.filter fun rule =>
    if e.model.roles.any (fun role => role.name == rule.ptype && role.fields.length == 3) then
      !domains.contains (rule.values[2]?.getD "")
    else if let .ok idx := e.getFieldIndex rule.ptype "dom" then !domains.contains (rule.values[idx]?.getD "")
    else true)

def Enforcer.getImplicitUsersForPermission (e : Enforcer) (permission : List String) : Except String (List String) := do
  let users := ((← e.getAllSubjects) ++ (e.getGroupingPolicy.filterMap (·[0]?))).eraseDups
  let roles := e.getAllRoles
  let mut result := []
  for user in users.filter (!roles.contains ·) do
    if ← e.enforce (user :: permission) then result := result ++ [user]
  return result

def Enforcer.getImplicitResourcesForUser (e : Enforcer) (user : String) (domain : Option String := none) :
    Except String (List (List String)) := do
  let permissions ← e.getImplicitPermissionsForUser user domain
  let mut result := []
  for permission in permissions do
    if permission[0]? == some user then
      result := result ++ [permission]
      continue
    let mut rows := [[user]]
    for token in permission.drop 1 do
      let users ← e.getImplicitUsersForRole token domain
      rows := (users ++ [token]).flatMap fun name => rows.map (· ++ [name])
    result := result ++ rows
  return result.eraseDups

def Enforcer.getAllowedObjectConditions (e : Enforcer) (user action conditionPrefix : String) : Except String (List String) := do
  let obj ← e.getFieldIndex "p" "obj"
  let act ← e.getFieldIndex "p" "act"
  let mut result := []
  for row in ← e.getImplicitPermissionsForUser user do
    if row[act]? == some action then
      let condition := row[obj]?.getD ""
      if !condition.startsWith conditionPrefix then throw "object condition has the wrong prefix"
      result := result ++ [String.ofList (condition.toList.drop conditionPrefix.length)]
  if result.isEmpty then throw "no allowed object conditions"
  return result

def Enforcer.getImplicitObjectPatternsForUser (e : Enforcer) (user domain action : String) : Except String (List String) := do
  let obj ← e.getFieldIndex "p" "obj"
  let act ← e.getFieldIndex "p" "act"
  return ((← e.getImplicitPermissionsForUser user (some domain)).filter
    (fun row => row[act]? == some action || row[act]? == some "*")).filterMap (·[obj]?) |>.eraseDups

def Enforcer.getImplicitUsersForResource (e : Enforcer) (resource : String)
    (domain : Option String := none) (resourceRoleType : String := "g2") : Except String (List (List String)) := do
  let sub ← e.getFieldIndex "p" "sub"
  let obj ← e.getFieldIndex "p" "obj"
  let dom := (e.getFieldIndex "p" "dom").toOption
  let types := ((e.getGroupingPolicy resourceRoleType).filter (fun row => row[0]? == some resource)).filterMap (·[1]?)
  let mut result := []
  for row in e.getPolicy do
    if row[obj]? != some resource && !types.contains (row[obj]?.getD "") then continue
    if domain.isSome && dom.bind (row[·]?) != domain then continue
    let subject := row[sub]?.getD ""
    if !(e.getAllRoles).contains subject then result := result ++ [row]
    else
      for user in ← e.getUsersForRole subject domain do
        result := result ++ [row.set sub user]
  return result.eraseDups

end Casbin
