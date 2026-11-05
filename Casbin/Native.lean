import Lean

namespace Casbin

@[extern "casbin_regex"]
private opaque nativeRegex (input pattern : @& String) (capture : Bool) : String

/-- RE2 is the native regular-expression primitive; authorization remains in Lean. -/
def runRegex (input pattern : String) (capture : Bool := false) : Except String Lean.Json := do
  -- RE2 has one extra escape that Go's regexp intentionally does not accept.
  let mut escaped := false
  for c in pattern.toList do
    if escaped then
      if c == 'C' then throw "invalid Go regexp escape: \\C"
      escaped := false
    else if c == '\\' then escaped := true
  let result ← Lean.Json.parse (nativeRegex input pattern capture)
  if let .ok error := result.getObjValAs? String "error" then throw error
  return result

end Casbin
