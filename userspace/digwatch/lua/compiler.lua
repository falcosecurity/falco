--[[
   Digwatch grammar and parser.

   Much of the scaffolding and helpers was derived from Andre Murbach Maidl's Lua parser (https://github.com/andremm/lua-parser).

   Parses regular filters following the existing sysdig filter syntax (*), as well as "macro" definitions. Macro definitions are written like:

   inbound: (syscall.type=listen and evt.dir='>') or (syscall.type=accept and evt.dir='<')

   (*) There is currently one known difference with the syntax implemented in libsinsp: In libsinsp, field names cannot start with 'a', 'o', or 'n'. With this parser they can.

--]]

local compiler = {}
compiler.parser = {}

local lpeg = require "lpeg"

lpeg.locale(lpeg)

local P, S, V = lpeg.P, lpeg.S, lpeg.V
local C, Carg, Cb, Cc = lpeg.C, lpeg.Carg, lpeg.Cb, lpeg.Cc
local Cf, Cg, Cmt, Cp, Ct = lpeg.Cf, lpeg.Cg, lpeg.Cmt, lpeg.Cp, lpeg.Ct
local alpha, digit, alnum = lpeg.alpha, lpeg.digit, lpeg.alnum
local xdigit = lpeg.xdigit
local space = lpeg.space


-- error message auxiliary functions

-- creates an error message for the input string
local function syntaxerror (errorinfo, pos, msg)
  local error_msg = "%s: syntax error, %s"
  return string.format(error_msg, pos, msg)
end

-- gets the farthest failure position
local function getffp (s, i, t)
  return t.ffp or i, t
end

-- gets the table that contains the error information
local function geterrorinfo ()
  return Cmt(Carg(1), getffp) * (C(V"OneWord") + Cc("EOF")) /
  function (t, u)
    t.unexpected = u
    return t
  end
end

-- creates an errror message using the farthest failure position
local function errormsg ()
  return geterrorinfo() /
  function (t)
    local p = t.ffp or 1
    local msg = "unexpected '%s', expecting %s"
    msg = string.format(msg, t.unexpected, t.expected)
    return nil, syntaxerror(t, p, msg)
  end
end

-- reports a syntactic error
local function report_error ()
  return errormsg()
end

--- sets the farthest failure position and the expected tokens
local function setffp (s, i, t, n)
  if not t.ffp or i > t.ffp then
    t.ffp = i
    t.list = {} ; t.list[n] = n
    t.expected = "'" .. n .. "'"
  elseif i == t.ffp then
    if not t.list[n] then
      t.list[n] = n
      t.expected = "'" .. n .. "', " .. t.expected
    end
  end
  return false
end

local function updateffp (name)
  return Cmt(Carg(1) * Cc(name), setffp)
end

-- regular combinators and auxiliary functions

local function token (pat, name)
  return pat * V"Skip" + updateffp(name) * P(false)
end

local function symb (str)
  return token (P(str), str)
end

local function kw (str)
  return token (P(str) * -V"idRest", str)
end


local function list (pat, sep)
   return Ct(pat^-1 * (sep * pat^0)^0) / function(elements) return {type = "List", elements=elements} end
end

--http://lua-users.org/wiki/StringTrim
function trim(s)
   if (type(s) ~= "string") then return s end
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function terminal (tag)
   -- Rather than trim the whitespace in this way, it would be nicer to exclude it from the capture...
   return token(V(tag), tag) / function (tok) return { type = tag, value = trim(tok)} end
end

local function unaryboolop (op, e)
  return { type = "UnaryBoolOp", operator = op, argument = e }
end

local function unaryrelop (e, op)
  return { type = "UnaryRelOp", operator = op, argument = e }
end

local function binaryop (e1, op, e2)
  if not op then
     return e1
  else
     return { type = "BinaryBoolOp", operator = op, left = e1, right = e2 }
  end
end

local function bool (pat, sep)
  return Cf(pat * Cg(sep * pat)^0, binaryop)
end

local function rel (left, sep, right)
   return left * sep * right / function(e1, op, e2) return { type = "BinaryRelOp", operator = op, left = e1, right = e2 } end
end

local function fix_str (str)
  str = string.gsub(str, "\\a", "\a")
  str = string.gsub(str, "\\b", "\b")
  str = string.gsub(str, "\\f", "\f")
  str = string.gsub(str, "\\n", "\n")
  str = string.gsub(str, "\\r", "\r")
  str = string.gsub(str, "\\t", "\t")
  str = string.gsub(str, "\\v", "\v")
  str = string.gsub(str, "\\\n", "\n")
  str = string.gsub(str, "\\\r", "\n")
  str = string.gsub(str, "\\'", "'")
  str = string.gsub(str, '\\"', '"')
  str = string.gsub(str, '\\\\', '\\')
  return str
end

-- grammar

local function filter(e)
   return {type = "Filter", value=e}
end

local function macro (name, filter)
   return {type = "MacroDef", name = name, value = filter}
end

local function outputformat (format)
   return {type = "OutputFormat", value = format}
end

local function functioncall (name, args)
   return {type = "FunctionCall", name = name, arguments = args}
end

local function rule(filter, output)
   if not output then
      output = outputformat("")
   end
   return {type = "Rule", filter = filter, output = output}
end

local G = {
   V"Start", -- Entry rule

   Start = V"Skip" * (V"Comment" + V"MacroDef" / macro + V"Rule" / rule)^-1 * -1 + report_error();

  -- Grammar
   Comment = P"#" * P(1)^0;

   Rule = V"Filter" / filter * ((V"Skip" * V"Pipe" * V"Skip" * V"Output")^-1 );

   Filter = V"OrExpression";
  OrExpression =
     bool(V"AndExpression", V"OrOp");

  AndExpression =
     bool(V"NotExpression", V"AndOp");

  NotExpression =
     V"UnaryBoolOp" * V"NotExpression" / unaryboolop +
     V"ExistsExpression";

  ExistsExpression =
     terminal "FieldName" * V"ExistsOp" / unaryrelop +
     V"MacroExpression";

  MacroExpression =
     terminal "Macro" +
     V"RelationalExpression";

  RelationalExpression =
     rel(terminal "FieldName", V"RelOp", V"Value") +
     rel(terminal "FieldName", V"InOp", V"InList") +
     V"PrimaryExp";

  PrimaryExp = symb("(") * V"Filter" * symb(")");

  MacroDef = (C(V"Macro") * V"Skip" * V"Colon" * (V"Filter"));

  FuncArgs = symb("(") * list(V"Value", symb(",")) * symb(")");
  Output = ((V"Name" * V"FuncArgs") / functioncall) + P(1)^0 / outputformat;

  -- Terminals
  Value = terminal "Number" + terminal "String" + terminal "BareString";

  InList = symb("(") * list(V"Value", symb(",")) * symb(")");


  -- Lexemes
  Space = space^1;
  Skip = (V"Space")^0;
  idStart = alpha + P("_");
  idRest = alnum + P("_");
  Identifier = V"idStart" * V"idRest"^0;
  Macro = V"idStart" * V"idRest"^0 * -P".";
  FieldName = V"Identifier" * (P"." + V"Identifier")^1 * (P"[" * V"Int" * P"]")^-1;
  Name = C(V"Identifier") * -V"idRest";
  Hex = (P("0x") + P("0X")) * xdigit^1;
  Expo = S("eE") * S("+-")^-1 * digit^1;
  Float = (((digit^1 * P(".") * digit^0) +
          (P(".") * digit^1)) * V"Expo"^-1) +
          (digit^1 * V"Expo");
  Int = digit^1;
  Number = C(V"Hex" + V"Float" + V"Int") /
           function (n) return tonumber(n) end;
  String = (P'"' * C(((P'\\' * P(1)) + (P(1) - P'"'))^0) * P'"' +  P"'" * C(((P"\\" * P(1)) + (P(1) - P"'"))^0) * P"'")  / function (s) return fix_str(s) end;
  BareString = C(((P(1) - S' (),='))^1);

  OrOp = kw("or") / "or";
  AndOp = kw("and") / "and";
  Colon = kw(":");
  Pipe = kw("|");
  RelOp = symb("=") / "=" +
          symb("==") / "==" +
          symb("!=") / "!=" +
          symb("<=") / "<=" +
          symb(">=") / ">=" +
          symb("<") / "<" +
          symb(">") / ">" +
          symb("contains") / "contains" +
          symb("icontains") / "icontains";
  InOp = kw("in") / "in";
  UnaryBoolOp = kw("not") / "not";
  ExistsOp = kw("exists") / "exists";

  -- for error reporting
  OneWord = V"Name" + V"Number" + V"String" +  P(1);
}

function map(f, arr)
   local res = {}
   for i,v in ipairs(arr) do
      res[i] = f(v)
   end
   return res
end

function foldr(f, acc, arr)
   for i,v in pairs(arr) do
      acc = f(acc, v)
   end
   return acc
end

--[[
   Traverses the AST and replaces `in` relational expressions with a sequence of ORs.

   For example, `a.b in [1, 2]` is expanded to `a.b = 1 or a.b = 2` (in ASTs)
--]]
function expand_in(node)
   local t = node.type

   if t == "Filter" then
      expand_in(node.value)

   elseif t == "UnaryBoolOp" then
      expand_in(node.argument)

   elseif t == "BinaryBoolOp" then
      expand_in(node.left)
      expand_in(node.right)

   elseif t == "BinaryRelOp" and node.operator == "in" then
      if (table.maxn(node.right.elements) == 0) then
         error ("In list with zero elements")
      end

      local mapper = function(element)
         return {
            type = "BinaryRelOp",
            operator = "=",
            left = node.left,
            right = element
         }
      end

      local equalities = map(mapper, node.right.elements)
      local lasteq = equalities[table.maxn(equalities)]
      equalities[table.maxn(equalities)] = nil

      local folder = function(left, right)
         return {
            type = "BinaryBoolOp",
            operator = "or",
            left = left,
            right = right
         }
      end
      lasteq = foldr(folder, lasteq, equalities)

      node.type=lasteq.type
      node.operator=lasteq.operator
      node.left=lasteq.left
      node.right=lasteq.right
   end
end

--[[

   Given a map of macro definitions, traverse AST and replace macro references
   with their definitions.

   The AST is changed in-place.

   The return value is a boolean which is true if any macro was
   substitued. This allows a caller to re-traverse until no more macros are
   found, a simple strategy for recursive resoltuions (e.g. when a macro
   definition uses another macro).

--]]
function expand_macros(ast, defs, changed)

   function copy(obj)
      if type(obj) ~= 'table' then return obj end
      local res = {}
      for k, v in pairs(obj) do res[copy(k)] = copy(v) end
      return res
   end

   if (ast.type == "Rule") then
      return expand_macros(ast.filter, defs, changed)
   elseif ast.type == "Filter" then
      if (ast.value.type == "Macro") then
         if (defs[ast.value.value] == nil) then
            error("Undefined macro '".. ast.value.value .. "' used in filter.")
         end
         ast.value = copy(defs[ast.value.value])
         changed = true
	 return changed
      end
      return expand_macros(ast.value, defs, changed)

   elseif ast.type == "BinaryBoolOp" then

      if (ast.left.type == "Macro") then
         if (defs[ast.left.value] == nil) then
            error("Undefined macro '".. ast.left.value .. "' used in filter.")
         end
         ast.left = copy(defs[ast.left.value])
         changed = true
      end

      if (ast.right.type == "Macro") then
         if (defs[ast.right.value] == nil) then
            error("Undefined macro ".. ast.right.value .. " used in filter.")
         end
         ast.right = copy(defs[ast.right.value])
         changed = true
      end

      local changed_left = expand_macros(ast.left, defs, false)
      local changed_right = expand_macros(ast.right, defs, false)
      return changed or changed_left or changed_right

   elseif ast.type == "UnaryBoolOp" then
      if (ast.argument.type == "Macro") then
         if (defs[ast.argument.value] == nil) then
            error("Undefined macro ".. ast.argument.value .. " used in filter.")
         end
         ast.argument = copy(defs[ast.argument.value])
         changed = true
      end
      return expand_macros(ast.argument, defs, changed)
   end
   return changed
end

function get_macros(ast, set)
   if (ast.type == "Macro") then
      set[ast.value] = true
      return set
   end

   if ast.type == "Filter" then
      return get_macros(ast.value, set)
   end

   if ast.type == "BinaryBoolOp" then
      local left = get_macros(ast.left, {})
      local right = get_macros(ast.right, {})

      for m, _ in pairs(left) do set[m] = true end
      for m, _ in pairs(right) do set[m] = true end

      return set
   end
   if ast.type == "UnaryBoolOp" then
      return get_macros(ast.argument, set)
   end
   return set
end

function check_macros(ast)
   local macros
   if (ast.type == "Rule") then
      macros = get_macros(ast.filter, {})
   elseif (ast.type == "MacroDef") then
      macros = get_macros(ast.value, {})
   else
      error ("Unexpected type: "..t)
   end

   for m, _ in pairs(macros) do
      if macros[m] == nil then
         error ("Undefined macro '"..m.."' used in '"..line.."'")
      end
   end
end

function print_ast(ast, level)
   local t = ast.type
   level = level or 0
   local prefix = string.rep(" ", level*2)
   level = level + 1

   if t == "Rule" then
      print_ast(ast.filter, level)
      if (ast.output) then
	 print(prefix.."| ")
	 print_ast(ast.output)
      end
   elseif t == "OutputFormat" then
      print(ast.value)

   elseif t == "FunctionCall" then
      print(ast.name .. "(" )
      print_ast(ast.arguments)
      print(")")

   elseif t == "Filter" then
      print_ast(ast.value, level)

   elseif t == "BinaryBoolOp" or t == "BinaryRelOp" then
      print(prefix..ast.operator)
      print_ast(ast.left, level)
      print_ast(ast.right, level)

   elseif t == "UnaryRelOp" or t == "UnaryBoolOp" then
      print (prefix..ast.operator)
      print_ast(ast.argument, level)

   elseif t == "List" then
      for i, v in ipairs(ast.elements) do
         print_ast(v, level)
      end

   elseif t == "FieldName" or t == "Number" or t == "String" or t == "BareString" or t == "Macro" then
      print (prefix..t.." "..ast.value)

   elseif t == "MacroDef" then
      -- don't print for now
   else
      error ("Unexpected type in print_ast: "..t)
   end
end
compiler.parser.print_ast = print_ast


--[[
   Parses a single line (which should be either a macro definition or a filter) and returns the AST.
--]]
function compiler.parser.parse_line (subject)
  local errorinfo = { subject = subject }
  lpeg.setmaxstack(1000)
  local ast, error_msg = lpeg.match(G, subject, nil, errorinfo)
  return ast, error_msg
end


--[[
   Compiles a single line from a digwatch ruleset and updates the passed-in macros table. Returns the AST of the line.
--]]
function compiler.compile_line(line, macro_defs)
   local ast, error_msg = compiler.parser.parse_line(line)

   if (error_msg) then
      print ("Compilation error: ", error_msg)
      error(error_msg)
   end

   if (type(ast) == "number") then
      -- hack: we get a number (# of matched chars) V"Skip" back if this line
      -- only contained whitespace. (According to docs 'v"Skip" / 0' in Start
      -- rule should not capture anything but it doesn't seem to work that
      -- way...)
      return {}
   end

   -- check that any macros used have already been defined
   check_macros(ast)

   if (ast.type == "MacroDef") then
      expand_in(ast.value)

      -- Parsed line is a macro definition, so update our dictionary of macros and
      -- return
      macro_defs[ast.name] = ast.value
      return ast

   elseif (ast.type == "Rule") then
      -- Line is a filter, so expand in-clauses and macro references, then
      -- stitch it into global ast

      expand_in(ast.filter)

      repeat
	 expanded  = expand_macros(ast, macro_defs, false)
      until expanded == false

   else
      error("Unexpected top-level AST type: "..ast.type)
   end

   return ast
end


return compiler
