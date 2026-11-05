import Casbin.Support
import Casbin.Config

namespace Casbin

def Enforcer.getModel (e : Enforcer) : Model := e.model
def Enforcer.fromModel (model : Model) (rules : List Rule := [])
    (functions : List (String × Function) := []) (valueFunctions : List (String × ValueFunction) := [])
    (effector : Option Effector := none) : Except String Enforcer :=
  Enforcer.fromText model.toText (serializePolicy rules) functions valueFunctions effector
def Enforcer.getRoleManager (e : Enforcer) (ptype : String := "g") : Option RoleManager := do
  if let some (_, manager) := e.roleManagers.find? (·.1 == ptype) then return manager
  if !e.model.roles.any (·.name == ptype) then none
  else
    let base := { e with roleManagers := [], roleSnapshot := none }
    return {
      hasLink := fun rules source target domain => { base with rules := rules }.hasLink source target domain ptype
      getRoles := fun rules user domain => { base with rules := rules }.getRolesForUser user domain ptype
      getUsers := fun rules role domain => { base with rules := rules }.getUsersForRole role domain ptype
    }
def Enforcer.setModel (e : Enforcer) (model : Model) : Except String Enforcer := do
  let updated ← Enforcer.fromText model.toText "" e.functions e.valueFunctions e.effector
  return { e with model := updated.model, rules := [], roleSnapshot := none, fieldIndices := [] }

def RuntimeEnforcer.getAdapter (e : RuntimeEnforcer) : IO (Option Adapter) := e.state.atomically do return (← get).adapter
def RuntimeEnforcer.getWatchers (e : RuntimeEnforcer) : IO (List Watcher) := e.state.atomically do return (← get).watchers
def RuntimeEnforcer.getDispatcher (e : RuntimeEnforcer) : IO (Option Dispatcher) := e.state.atomically do return (← get).dispatcher
def RuntimeEnforcer.loadModel (e : RuntimeEnforcer) (path : System.FilePath) : IO Unit := do
  let model ← Model.fromFile path
  e.configure (fun previous => previous.setModel model)
def RuntimeEnforcer.setEffector (e : RuntimeEnforcer) (effector : Effector) : IO Unit :=
  e.configure (fun previous => .ok (previous.setEffector effector))
def RuntimeEnforcer.setRoleManager (e : RuntimeEnforcer) (manager : RoleManager) (ptype : String := "g") : IO Unit :=
  e.configure (fun previous => previous.setRoleManager manager ptype)
def RuntimeEnforcer.enableEnforce (e : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  e.configure (fun previous => .ok (previous.enableEnforce enabled))
def RuntimeEnforcer.enableAcceptJsonRequest (e : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  e.configure (fun previous => .ok (previous.enableAcceptJsonRequest enabled))
def RuntimeEnforcer.enableAutoBuildRoleLinks (e : RuntimeEnforcer) (enabled : Bool) : IO Unit :=
  e.configure (fun previous => .ok (previous.enableAutoBuildRoleLinks enabled))
def RuntimeEnforcer.buildRoleLinks (e : RuntimeEnforcer) : IO Unit := e.configure (fun previous => .ok previous.buildRoleLinks)
def RuntimeEnforcer.addRoleForUser (e : RuntimeEnforcer) (user role : String) (domain : Option String := none) : IO Bool :=
  e.mutate (fun previous => previous.addRoleForUser user role domain)
def RuntimeEnforcer.deleteRoleForUser (e : RuntimeEnforcer) (user role : String) (domain : Option String := none) : IO Bool :=
  e.mutate (fun previous => previous.deleteRoleForUser user role domain)
def RuntimeEnforcer.deleteUser (e : RuntimeEnforcer) (user : String) : IO Bool := e.mutate (fun previous => previous.deleteUser user)
def RuntimeEnforcer.deleteRole (e : RuntimeEnforcer) (role : String) : IO Bool := e.mutate (fun previous => previous.deleteRole role)
def RuntimeEnforcer.deleteDomains (e : RuntimeEnforcer) (domains : List String) : IO Bool := e.mutate (fun previous => previous.deleteDomains domains)

def Enforcer.getFilteredNamedPolicyWithMatcher (e : Enforcer) (ptype source : String) :
    Except String (List (List String)) := do
  let defn ← findDefinition e.model.policies ptype
  if (source.splitOn (ptype ++ ".")).length < 2 then return []
  let mut result := []
  for row in e.getPolicy ptype do
    let environment := (defn.fields.zip row).map fun (field, value) => (ptype ++ "." ++ field, Value.text value)
    if ← (← e.evaluateExpression source environment).asBool then result := result ++ [row]
  return result

def Enforcer.hasGroupingPolicy (e : Enforcer) (values : List String) (ptype : String := "g") : Bool := e.hasPolicy values ptype
def Enforcer.addGroupingPoliciesEx (e : Enforcer) (values : List (List String)) (ptype : String := "g") :
    Except String (Enforcer × Bool) := e.addGroupingPolicies values ptype true
def Enforcer.getNamedPolicy (e : Enforcer) (ptype : String) := e.getPolicy ptype
def Enforcer.getNamedGroupingPolicy (e : Enforcer) (ptype : String) := e.getGroupingPolicy ptype
def Enforcer.getFilteredNamedPolicy (e : Enforcer) (ptype : String) (index : Nat) (values : List String) := e.getFilteredPolicy index values ptype
def Enforcer.getFilteredNamedGroupingPolicy (e : Enforcer) (ptype : String) (index : Nat) (values : List String) := e.getFilteredGroupingPolicy index values ptype
def Enforcer.getAllNamedSubjects (e : Enforcer) (ptype : String) := e.getAllSubjects ptype
def Enforcer.getAllNamedObjects (e : Enforcer) (ptype : String) := e.getAllObjects ptype
def Enforcer.getAllNamedActions (e : Enforcer) (ptype : String) := e.getAllActions ptype
def Enforcer.getAllNamedRoles (e : Enforcer) (ptype : String) := e.getAllRoles ptype
def Enforcer.getRolesForUserInDomain (e : Enforcer) (user domain : String) := e.getRolesForUser user (some domain)
def Enforcer.getUsersForRoleInDomain (e : Enforcer) (role domain : String) := e.getUsersForRole role (some domain)
def Enforcer.getPermissionsForUserInDomain (e : Enforcer) (user domain : String) := e.getPermissionsForUser user (some domain)
def Enforcer.addRoleForUserInDomain (e : Enforcer) (user role domain : String) := e.addRoleForUser user role (some domain)
def Enforcer.deleteRoleForUserInDomain (e : Enforcer) (user role domain : String) := e.deleteRoleForUser user role (some domain)
def Enforcer.deleteRolesForUserInDomain (e : Enforcer) (user domain : String) := e.deleteRolesForUser user (some domain)
def Enforcer.deleteAllUsersByDomain (e : Enforcer) (domain : String) := e.deleteDomains [domain]
def Enforcer.getNamedImplicitRolesForUser (e : Enforcer) (ptype user : String) (domain : Option String := none) := e.getImplicitRolesForUser user domain ptype
def Enforcer.getNamedPermissionsForUser (e : Enforcer) (ptype user : String) (domain : Option String := none) := e.getPermissionsForUser user domain ptype
def Enforcer.getNamedImplicitPermissionsForUser (e : Enforcer) (ptype gtype user : String) (domain : Option String := none) := e.getImplicitPermissionsForUser user domain ptype gtype
def Enforcer.getNamedImplicitUsersForResource (e : Enforcer) (ptype resource : String) := e.getImplicitUsersForResource resource none ptype
def Enforcer.getImplicitUsersForResourceByDomain (e : Enforcer) (resource domain : String) := e.getImplicitUsersForResource resource (some domain)

def PolicyEvent.added (event : PolicyEvent) : List Rule := event.after.filter (!event.before.contains ·)
def PolicyEvent.removed (event : PolicyEvent) : List Rule := event.before.filter (!event.after.contains ·)

def Enforcer.hasNamedPolicy (e : Enforcer) (ptype : String) (row : List String) := e.hasPolicy row ptype
def Enforcer.addNamedPolicy (e : Enforcer) (ptype : String) (row : List String) := e.addPolicy row ptype
def Enforcer.removeNamedPolicy (e : Enforcer) (ptype : String) (row : List String) := e.removePolicy row ptype
def Enforcer.addNamedPolicies (e : Enforcer) (ptype : String) (rows : List (List String)) := e.addPolicies rows ptype
def Enforcer.removeNamedPolicies (e : Enforcer) (ptype : String) (rows : List (List String)) := e.removePolicies rows ptype
def Enforcer.addNamedPoliciesEx (e : Enforcer) (ptype : String) (rows : List (List String)) := e.addPoliciesEx rows ptype
def Enforcer.updateNamedPolicy (e : Enforcer) (ptype : String) (oldRow newRow : List String) := e.updatePolicy oldRow newRow ptype
def Enforcer.updateNamedPolicies (e : Enforcer) (ptype : String) (oldRows newRows : List (List String)) := e.updatePolicies oldRows newRows ptype
def Enforcer.removeFilteredNamedPolicy (e : Enforcer) (ptype : String) (index : Nat) (values : List String) := e.removeFilteredPolicy index values ptype
def Enforcer.hasNamedGroupingPolicy (e : Enforcer) (ptype : String) (row : List String) := e.hasGroupingPolicy row ptype
def Enforcer.addNamedGroupingPolicy (e : Enforcer) (ptype : String) (row : List String) := e.addGroupingPolicy row ptype
def Enforcer.removeNamedGroupingPolicy (e : Enforcer) (ptype : String) (row : List String) := e.removeGroupingPolicy row ptype
def Enforcer.addNamedGroupingPolicies (e : Enforcer) (ptype : String) (rows : List (List String)) := e.addGroupingPolicies rows ptype
def Enforcer.removeNamedGroupingPolicies (e : Enforcer) (ptype : String) (rows : List (List String)) := e.removeGroupingPolicies rows ptype
def Enforcer.addNamedGroupingPoliciesEx (e : Enforcer) (ptype : String) (rows : List (List String)) := e.addGroupingPoliciesEx rows ptype
def Enforcer.updateNamedGroupingPolicy (e : Enforcer) (ptype : String) (oldRow newRow : List String) := e.updateGroupingPolicy oldRow newRow ptype
def Enforcer.updateNamedGroupingPolicies (e : Enforcer) (ptype : String) (oldRows newRows : List (List String)) := e.updateGroupingPolicies oldRows newRows ptype
def Enforcer.removeFilteredNamedGroupingPolicy (e : Enforcer) (ptype : String) (index : Nat) (values : List String) := e.removeFilteredGroupingPolicy index values ptype
def Enforcer.updateFilteredNamedPolicies (e : Enforcer) (ptype : String) (rows : List (List String)) (index : Nat) (values : List String) := e.updateFilteredPolicies rows index values ptype

end Casbin
