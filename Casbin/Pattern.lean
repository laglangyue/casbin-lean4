import Std

namespace Casbin

/-- A small regular-expression engine. Unsupported RE2 extensions are errors. -/
private inductive Pattern where
  | empty
  | char (value : Char)
  | any
  | charClass (negated : Bool) (ranges : List (Char × Char))
  | seq (parts : List Pattern)
  | alt (parts : List Pattern)
  | star (part : Pattern)
  | start
  | finish
  deriving Inhabited

private def escape (c : Char) : Except String Pattern :=
  match c with
  | 'd' => .ok (.charClass false [('0', '9')])
  | 'D' => .ok (.charClass true [('0', '9')])
  | 'w' => .ok (.charClass false [('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')])
  | 'W' => .ok (.charClass true [('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')])
  | 's' => .ok (.charClass false [(' ', ' '), ('\t', '\r')])
  | 'S' => .ok (.charClass true [(' ', ' '), ('\t', '\r')])
  | 'n' => .ok (.char '\n')
  | 't' => .ok (.char '\t')
  | 'r' => .ok (.char '\r')
  | _ => if c.isAlphanum then .error s!"unsupported regex escape: \\{c}"
         else .ok (.char c)

private partial def classChars (cs : List Char) (acc : List (Char × Bool) := []) :
    Except String (List (Char × Bool) × List Char) := do
  match cs with
  | [] => throw "unterminated regex character class"
  | ']' :: rest =>
    if acc.isEmpty then throw "empty regex character class"
    return (acc.reverse, rest)
  | '\\' :: c :: rest =>
    match ← escape c with
    | .char d => classChars rest ((d, true) :: acc)
    | _ => throw "character-class escapes inside [] are not supported"
  | c :: rest => classChars rest ((c, false) :: acc)

private def classRanges : List (Char × Bool) → Except String (List (Char × Char))
  | (a, _) :: ('-', false) :: (b, _) :: rest => do
    if a.toNat > b.toNat then throw "reversed regex character range"
    return (a, b) :: (← classRanges rest)
  | (c, _) :: rest => do return (c, c) :: (← classRanges rest)
  | [] => .ok []

mutual
private partial def parseAlt (cs : List Char) : Except String (Pattern × List Char) := do
  let (lhs, rest) ← parseSeq cs []
  match rest with
  | '|' :: rest =>
    let (rhs, rest) ← parseAlt rest
    return (.alt [lhs, rhs], rest)
  | _ => return (lhs, rest)

private partial def parseSeq (cs : List Char) (acc : List Pattern) :
    Except String (Pattern × List Char) := do
  match cs with
  | [] | ')' :: _ | '|' :: _ => return (.seq acc.reverse, cs)
  | _ =>
    let (atom, rest) ← parseAtom cs
    let (atom, rest) := match rest with
      | '*' :: rest => (Pattern.star atom, rest)
      | '+' :: rest => (Pattern.seq [atom, .star atom], rest)
      | '?' :: rest => (Pattern.alt [.empty, atom], rest)
      | _ => (atom, rest)
    parseSeq rest (atom :: acc)

private partial def parseAtom (cs : List Char) : Except String (Pattern × List Char) := do
  match cs with
  | '(' :: '?' :: _ => throw "regex group extensions are not supported"
  | '(' :: rest =>
    let (pat, rest) ← parseAlt rest
    match rest with
    | ')' :: rest => return (pat, rest)
    | _ => throw "unterminated regex group"
  | '[' :: rest =>
    let negated := rest.head? == some '^'
    let (chars, rest) ← classChars (if negated then rest.drop 1 else rest)
    return (.charClass negated (← classRanges chars), rest)
  | '\\' :: c :: rest => return (← escape c, rest)
  | '.' :: rest => return (.any, rest)
  | '^' :: rest => return (.start, rest)
  | '$' :: rest => return (.finish, rest)
  | c :: rest =>
    if ['*', '+', '?', '{', '}', ']', '\\'].contains c then
      throw s!"unsupported or misplaced regex token: {c}"
    return (.char c, rest)
  | [] => throw "expected regex atom"
end

private def compile (source : String) : Except String Pattern := do
  let (pat, rest) ← parseAlt source.toList
  if !rest.isEmpty then throw "unexpected closing regex group"
  return pat

private partial def positions (pat : Pattern) (input : Array Char) (pos : Nat) : List Nat := Id.run do
  match pat with
  | .empty => return [pos]
  | .start => return if pos == 0 then [pos] else []
  | .finish => return if pos == input.size then [pos] else []
  | .char c => return if input[pos]? == some c then [pos + 1] else []
  | .any => return if pos < input.size && input[pos]? != some '\n' then [pos + 1] else []
  | .charClass negated ranges =>
    match input[pos]? with
    | none => return []
    | some c =>
      let found := ranges.any fun (lo, hi) => lo.toNat ≤ c.toNat && c.toNat ≤ hi.toNat
      return if found != negated then [pos + 1] else []
  | .alt parts => return (parts.flatMap fun p => positions p input pos).eraseDups
  | .seq parts =>
    let mut current := [pos]
    for p in parts do
      current := (current.flatMap fun i => positions p input i).eraseDups
      if current.isEmpty then break
    return current
  | .star p =>
    let mut seen := [pos]
    let mut frontier := [pos]
    -- Every new state consumes at least one character. Nullable loops terminate too.
    for _ in [:input.size + 1] do
      let next := (frontier.flatMap fun i => positions p input i).eraseDups
      frontier := next.filter fun i => !seen.contains i
      if frontier.isEmpty then break
      seen := seen ++ frontier
    return seen

def regexMatch (input source : String) : Except String Bool := do
  let pat ← compile source
  let chars := input.toList.toArray
  return (List.range (chars.size + 1)).any fun pos => !(positions pat chars pos).isEmpty

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
      if name.isEmpty then throw "empty path parameter"
      return "[^/]+" ++ (← replaceParams (rest.drop name.length) colon)
    return ":" ++ (← replaceParams rest colon)
  | '{' :: rest =>
    if colon then return "{" ++ (← replaceParams rest colon)
    let name := rest.takeWhile (· != '}')
    if name.isEmpty || name.contains '/' || rest.length == name.length then
      throw "invalid path parameter"
    return "[^/]+" ++ (← replaceParams (rest.drop (name.length + 1)) colon)
  | c :: rest => return String.singleton c ++ (← replaceParams rest colon)

def keyMatch2 (input pattern : String) : Except String Bool := do
  if pattern == "*" then return true
  regexMatch input ("^" ++ (← replaceParams (pattern.replace "/*" "/.*").toList true) ++ "$")

def keyMatch3 (input pattern : String) : Except String Bool := do
  if pattern == "*" then return true
  regexMatch input ("^" ++ (← replaceParams (pattern.replace "/*" "/.*").toList false) ++ "$")

def keyMatch5 (input pattern : String) : Except String Bool :=
  keyMatch3 ((input.splitOn "?").headD "") pattern

private def regexLiteral (c : Char) : String :=
  if "\\.+*?()|[]{}^$".contains c then "\\" ++ String.singleton c else String.singleton c

private partial def globRegex (cs : List Char) : Except String String := do
  match cs with
  | [] => return ""
  | '*' :: '*' :: '/' :: rest => return "(.*/)?" ++ (← globRegex rest)
  | '*' :: '*' :: rest => return ".*" ++ (← globRegex rest)
  | '*' :: rest => return "[^/]*" ++ (← globRegex rest)
  | '?' :: rest => return "[^/]" ++ (← globRegex rest)
  | '[' :: rest =>
    let (chars, rest) ← classChars (if rest.head? == some '!' then '^' :: rest.drop 1 else rest)
    -- Preserve class syntax, including ranges, for the regex parser.
    let text := String.join (chars.map fun (c, escaped) =>
      (if escaped then "\\" else "") ++ String.singleton c)
    return "[" ++ text ++ "]" ++ (← globRegex rest)
  | '\\' :: c :: rest => return regexLiteral c ++ (← globRegex rest)
  | '{' :: _ | '}' :: _ => throw "glob brace expansion is not supported"
  | c :: rest => return regexLiteral c ++ (← globRegex rest)

def globMatch (input pattern : String) : Except String Bool := do
  regexMatch input ("^" ++ (← globRegex pattern.toList) ++ "$")

end Casbin
