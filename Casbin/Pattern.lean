import Casbin.Native

namespace Casbin

private def regexCaptures (input source : String) : Except String (Option (List (String × String))) := do
  let result ← runRegex input source true
  if !(← result.getObjValAs? Bool "match") then return none
  return some (← result.getObjValAs? (List (String × String)) "captures")

def regexMatch (input source : String) : Except String Bool := do
  (← runRegex input source).getObjValAs? Bool "match"

/-- Casbin's prefix wildcard: the first * consumes the remaining suffix. -/
def keyMatch (input pattern : String) : Bool :=
  if pattern.contains '*' then input.startsWith (String.ofList (pattern.toList.takeWhile (· != '*')))
  else input == pattern

private partial def replaceParams (cs : List Char) (colon : Bool) : Except String String := do
  match cs with
  | [] => return ""
  | ':' :: rest =>
    if colon then
      let name := rest.takeWhile (· != '/')
      if name.isEmpty then return ":" ++ (← replaceParams rest colon)
      return "[^/]+" ++ (← replaceParams (rest.drop name.length) colon)
    return ":" ++ (← replaceParams rest colon)
  | '{' :: rest =>
    if colon then return "{" ++ (← replaceParams rest colon)
    let segment := rest.takeWhile (· != '/')
    let some idx := (segment.zipIdx.filter (fun (c, _) => c == '}')).getLast?.map Prod.snd |
      return "{" ++ (← replaceParams rest colon)
    if idx == 0 then return "{}" ++ (← replaceParams (rest.drop 1) colon)
    return "[^/]+" ++ (← replaceParams (rest.drop (idx + 1)) colon)
  | c :: rest => return String.singleton c ++ (← replaceParams rest colon)

def keyMatch2 (input pattern : String) : Except String Bool := do
  if pattern == "*" then return true
  regexMatch input ("^" ++ (← replaceParams (pattern.replace "/*" "/.*").toList true) ++ "$")

def keyMatch3 (input pattern : String) : Except String Bool := do
  if pattern == "*" then return true
  regexMatch input ("^" ++ (← replaceParams (pattern.replace "/*" "/.*").toList false) ++ "$")

def keyMatch5 (input pattern : String) : Except String Bool :=
  keyMatch3 ((input.splitOn "?").headD "") pattern

def keyGet (input pattern : String) : String :=
  let head := pattern.toList.takeWhile (· != '*')
  if pattern.contains '*' && keyMatch input pattern then String.ofList (input.toList.drop head.length) else ""

private partial def captureParams (cs : List Char) (colon : Bool) (names : List String := []) (lazyCapture : Bool := false) :
    Except String (String × List String) := do
  match cs with
  | [] => return ("", names)
  | ':' :: rest =>
    if colon then
      let name := rest.takeWhile (· != '/')
      if name.isEmpty then
        let (tail, names) ← captureParams rest colon names lazyCapture
        return (":" ++ tail, names)
      let label := "casbin" ++ toString names.length
      let (tail, names) ← captureParams (rest.drop name.length) colon (names ++ [String.ofList name]) lazyCapture
      return ("(?P<" ++ label ++ ">[^/]+" ++ (if lazyCapture then "?" else "") ++ ")" ++ tail, names)
    let (tail, names) ← captureParams rest colon names lazyCapture
    return (":" ++ tail, names)
  | '{' :: rest =>
    let name := rest.takeWhile (· != '}')
    if !colon && !name.isEmpty && !name.contains '/' && rest.length > name.length then
      let label := "casbin" ++ toString names.length
      let (tail, names) ← captureParams (rest.drop (name.length + 1)) colon (names ++ [String.ofList name]) lazyCapture
      return ("(?P<" ++ label ++ ">[^/]+" ++ (if lazyCapture then "?" else "") ++ ")" ++ tail, names)
    let (tail, names) ← captureParams rest colon names lazyCapture
    return ("\\{" ++ tail, names)
  | c :: rest =>
    let (tail, names) ← captureParams rest colon names lazyCapture
    return (String.singleton c ++ tail, names)

private def keyGetParam (input pattern name : String) (colon : Bool) : Except String String := do
  let (source, names) ← captureParams (pattern.replace "/*" "/.*").toList colon [] (!colon)
  let result ← regexCaptures input ("^" ++ source ++ "$")
  let some bindings := result | return ""
  let some idx := names.findIdx? (· == name) | return ""
  return ((bindings.find? (·.1 == "casbin" ++ toString idx)).map Prod.snd).getD ""

def keyGet2 (input pattern name : String) : Except String String := keyGetParam input pattern name true
def keyGet3 (input pattern name : String) : Except String String := keyGetParam input pattern name false

def keyMatch4 (input pattern : String) : Except String Bool := do
  if pattern == "*" then return true
  let (source, names) ← captureParams (pattern.replace "/*" "/.*").toList false
  let some bindings ← regexCaptures input ("^" ++ source ++ "$") | return false
  let mut assigned : List (String × String) := []
  for (name, idx) in names.zipIdx do
    let value := ((bindings.find? (·.1 == "casbin" ++ toString idx)).map Prod.snd).getD ""
    if let some (_, previous) := assigned.find? (·.1 == name) then
      if value != previous then return false
    else assigned := assigned ++ [(name, value)]
  return true

private def regexLiteral (c : Char) : String :=
  if "\\.+*?()|[]{}^$".contains c then "\\" ++ String.singleton c else String.singleton c

mutual
private partial def globRegex (cs : List Char) (atStart : Bool := true) : Except String String := do
  match cs with
  | [] => return ""
  | '/' :: '*' :: '*' :: [] => return "(?:/.*)?"
  | '*' :: '*' :: '/' :: rest =>
    return (if atStart then "(?:.*/)?" else "[^/]*/") ++ (← globRegex rest true)
  | '*' :: '*' :: rest =>
    return (if atStart && rest.isEmpty then ".*" else "[^/]*") ++ (← globRegex rest false)
  | '*' :: rest => return "[^/]*" ++ (← globRegex rest false)
  | '?' :: rest => return "[^/]" ++ (← globRegex rest false)
  | '[' :: rest =>
    let negated := rest.head? == some '!' || rest.head? == some '^'
    let rest := if negated then rest.drop 1 else rest
    let chars := rest.takeWhile (· != ']')
    if chars.isEmpty || chars.length == rest.length then throw "invalid glob character class"
    return "[" ++ (if negated then "^" else "") ++ String.ofList chars ++ "]" ++
      (← globRegex (rest.drop (chars.length + 1)) false)
  | '\\' :: c :: rest => return regexLiteral c ++ (← globRegex rest false)
  | '{' :: rest =>
    let (branches, tail) ← globBranches rest 0 [] []
    let alternatives ← branches.mapM (fun branch => globRegex branch atStart)
    return "(?:" ++ String.intercalate "|" alternatives ++ ")" ++ (← globRegex tail false)
  | '}' :: _ => throw "unmatched glob brace"
  | c :: rest => return regexLiteral c ++ (← globRegex rest (c == '/'))

private partial def globBranches (cs : List Char) (depth : Nat) (current : List Char)
    (branches : List (List Char)) : Except String (List (List Char) × List Char) := do
  match cs with
  | [] => throw "unterminated glob brace"
  | '\\' :: c :: rest => globBranches rest depth (c :: '\\' :: current) branches
  | '{' :: rest => globBranches rest (depth + 1) ('{' :: current) branches
  | '}' :: rest =>
    if depth == 0 then return (branches ++ [current.reverse], rest)
    globBranches rest (depth - 1) ('}' :: current) branches
  | ',' :: rest =>
    if depth == 0 then globBranches rest 0 [] (branches ++ [current.reverse])
    else globBranches rest depth (',' :: current) branches
  | c :: rest => globBranches rest depth (c :: current) branches
end

def globMatch (input pattern : String) : Except String Bool := do
  regexMatch input ("^" ++ (← globRegex pattern.toList) ++ "$")

end Casbin
