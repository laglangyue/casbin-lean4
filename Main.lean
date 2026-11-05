import Casbin
import Lean

open Casbin Lean

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def decisionJson (d : Decision) : Json :=
  Json.mkObj [("allow", toJson d.allow), ("explain", toJson d.explain)]

private def help : String :=
  "Casbin Lean 4\n\n" ++
  "  casbin demo\n" ++
  "  casbin enforce MODEL.conf POLICY.csv SUBJECT OBJECT ACTION ...\n" ++
  "  casbin batch MODEL.conf POLICY.csv REQUESTS.json\n\n" ++
  "  casbin enforce-json MODEL.conf POLICY.csv REQUEST.json\n" ++
  "  casbin validate MODEL.conf POLICY.csv\n" ++
  "  casbin export-js MODEL.conf POLICY.csv USER\n" ++
  "  casbin save-db MODEL.conf POLICY.csv DATABASE.sqlite\n" ++
  "  casbin enforce-db MODEL.conf DATABASE.sqlite REQUEST.json\n" ++
  "  casbin explain MODEL.conf POLICY.csv REQUEST.json ENDPOINT AI_MODEL\n\n" ++
  "Requests follow model field order. JSON requests accept strings, numbers, booleans and objects.\n" ++
  "explain uses CASBIN_AI_KEY and sends the model, policies and request to the supplied endpoint.\n" ++
  "enforce: exit 0 = allowed, 1 = denied, 2 = error. batch: exit 0 = processed, 2 = error."

private def demo : IO UInt32 := do
  let model := "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n" ++
    "[role_definition]\ng = _, _\n[policy_effect]\ne = some(where (p.eft == allow))\n" ++
    "[matchers]\nm = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n"
  let e ← unwrap (Enforcer.fromText model "p, reader, report, read\ng, alice, reader\n")
  for request in [["alice", "report", "read"], ["alice", "report", "write"], ["bob", "report", "read"]] do
    let result ← unwrap (e.enforceEx request)
    IO.println (Json.mkObj [("request", toJson request), ("decision", decisionJson result)]).compress
  return 0

private def run (args : List String) : IO UInt32 := do
  match args with
  | [] | ["demo"] => demo
  | ["--help"] | ["-h"] => IO.println help; return 0
  | "enforce" :: model :: policy :: request =>
    let e ← Enforcer.fromFiles model policy
    let result ← e.enforceValuesIO (request.map Value.text)
    IO.println (decisionJson result).compress
    return if result.allow then 0 else 1
  | ["batch", model, policy, requestsPath] =>
    let e ← Enforcer.fromFiles model policy
    let json ← unwrap (Json.parse (← IO.FS.readFile requestsPath))
    let requests : List (List Value) ← unwrap (fromJson? json)
    let decisions ← requests.mapM fun r => e.enforceValuesIO r
    IO.println (Json.arr (decisions.map decisionJson).toArray).compress
    return 0
  | ["enforce-json", model, policy, requestPath] =>
    let e ← Enforcer.fromFiles model policy
    let request : List Value ← unwrap (fromJson? (← unwrap (Json.parse (← IO.FS.readFile requestPath))))
    let result ← e.enforceValuesIO request
    IO.println (decisionJson result).compress
    return if result.allow then 0 else 1
  | ["validate", model, policy] =>
    let e ← Enforcer.fromFiles model policy
    for role in e.model.roles do unwrap (e.detectCycles role.name)
    IO.println (Json.mkObj [("valid", .bool true), ("policyCount", toJson e.rules.length)]).compress
    return 0
  | ["export-js", model, policy, user] =>
    let e ← Enforcer.fromFiles model policy
    IO.print (e.casbinJsGetPermissionForUser user)
    return 0
  | ["save-db", model, policy, database] =>
    let e ← Enforcer.fromFiles model policy
    (Adapter.sqlite database).save e.model e.rules
    IO.println (Json.mkObj [("saved", .bool true), ("policyCount", toJson e.rules.length)]).compress
    return 0
  | ["enforce-db", model, database, requestPath] =>
    let e ← unwrap (Enforcer.fromText (← IO.FS.readFile model) "")
    let runtime ← RuntimeEnforcer.new e (some (Adapter.sqlite database))
    let request : List Value ← unwrap (fromJson? (← unwrap (Json.parse (← IO.FS.readFile requestPath))))
    let result ← runtime.enforceValuesEx request
    IO.println (decisionJson result).compress
    return if result.allow then 0 else 1
  | ["explain", model, policy, requestPath, endpoint, aiModel] =>
    let e ← Enforcer.fromFiles model policy
    let request : List Value ← unwrap (fromJson? (← unwrap (Json.parse (← IO.FS.readFile requestPath))))
    let explanation ← e.explain request { endpoint := endpoint, model := aiModel, apiKey := (← IO.getEnv "CASBIN_AI_KEY").getD "" }
    IO.println (Json.mkObj [("explanation", .str explanation)]).compress
    return 0
  | _ => throw (IO.userError help)

def main (args : List String) : IO UInt32 := do
  try run args
  catch error =>
    (← IO.getStderr).putStrLn s!"error: {error}"
    return 2
