"""Local provenance of key/IV material linked to a real Cipher.init AST node.

No byte values or key strings are returned. Array aliases share mutable state;
SecretKeySpec/IvParameterSpec/GCMParameterSpec snapshot their input provenance.
This is a deliberately bounded static analysis, not execution or whole-program
dataflow. Unknown mutation/branching causes abstention rather than a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from copy import copy
import re


@dataclass
class BytesState:
    origin: str  # constant, runtime, unknown
    length: int | None
    line: int | None
    strings: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Key:
    material: BytesState
    algorithm: str | None


@dataclass(frozen=True)
class Params:
    material: BytesState
    kind: str


@dataclass(frozen=True)
class Factory:
    kind: str
    algorithm: str | None = None


def inspect_materials(unit, source: str) -> dict:
    from javalang import tree as t

    findings, unresolved, observations = [], [], []
    secret_strings = set()
    has_materials = False
    lines = source.splitlines()
    shadowed = {node.name for _, node in unit.filter(t.ClassDeclaration)}

    def line(node):
        return node.position.line if getattr(node, "position", None) else None

    def name(reference):
        parts = []
        while reference:
            parts.append(reference.name)
            reference = getattr(reference, "sub_type", None)
        return parts[-1] if parts else ""

    def unknown(node, reason):
        unresolved.append({"line": line(node), "reason": reason})

    def primitive(node, env):
        if isinstance(node, t.Literal):
            raw = node.value
            if node.prefix_operators or node.postfix_operators:
                return None
            if raw.startswith('"') and raw.endswith('"') and "\\" not in raw:
                return raw[1:-1]
            if re.fullmatch(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)", raw):
                text = raw.replace("_", "")
                try:
                    return int(text, 16 if text.lower().startswith("0x") else 2 if text.lower().startswith("0b") else 8 if text.startswith("0") and len(text) > 1 else 10)
                except ValueError:
                    return None
        if isinstance(node, t.MemberReference) and not node.selectors and not node.prefix_operators and not node.postfix_operators:
            if not node.qualifier:
                value = env.get(node.member)
                return value if isinstance(value, (str, int)) else None
            if node.qualifier in {"Cipher", "javax.crypto.Cipher"} and "Cipher" not in shadowed:
                return {"ENCRYPT_MODE": 1, "DECRYPT_MODE": 2, "WRAP_MODE": 3, "UNWRAP_MODE": 4}.get(node.member)
        if isinstance(node, t.BinaryOperation) and node.operator == "+":
            left, right = primitive(node.operandl, env), primitive(node.operandr, env)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return None

    def snapshot(value, node):
        return replace(value) if isinstance(value, BytesState) else BytesState("unknown", None, line(node))

    def constant_element(node, env):
        if isinstance(node, t.Cast):
            return name(node.type) == "byte" and constant_element(node.expression, env)
        if isinstance(node, t.Literal) and not node.value.startswith(('"', "'")):
            return bool(re.fullmatch(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)", node.value))
        return isinstance(primitive(node, env), int)

    def encoded_length(text, arguments, env):
        # Never assume Java's platform-default encoding is UTF-8.
        if len(arguments) == 1:
            arg = arguments[0]
            utf8_constant = isinstance(arg, t.MemberReference) and arg.qualifier in {"StandardCharsets", "java.nio.charset.StandardCharsets"} and arg.member == "UTF_8"
            charset = primitive(arg, env)
            if utf8_constant or (isinstance(charset, str) and charset.upper() in {"UTF-8", "UTF8"}):
                return len(text.encode("utf-8"))
        return None

    def resolve(node, env):
        nonlocal has_materials
        if node is None:
            return None
        if isinstance(node, (t.MethodInvocation, t.ClassCreator)) and node.selectors:
            base_node = copy(node)
            base_node.selectors = []
            value = resolve(base_node, env)
            for selector in node.selectors:
                if isinstance(selector, t.MethodInvocation) and isinstance(value, Factory) and value.kind == "KeyGenerator" and selector.member == "generateKey" and not selector.arguments:
                    value = Key(BytesState("runtime", None, line(selector)), value.algorithm)
                elif isinstance(selector, t.MethodInvocation) and isinstance(value, Factory) and value.kind == "SecureRandom" and selector.member == "generateSeed" and len(selector.arguments) == 1:
                    size = primitive(selector.arguments[0], env)
                    value = BytesState("runtime", size if isinstance(size, int) else None, line(selector))
                elif isinstance(selector, t.MethodInvocation) and isinstance(value, str) and selector.member == "getBytes":
                    value = BytesState("constant", encoded_length(value, selector.arguments, env), line(selector), frozenset({value}))
                else:
                    return None
            return value
        if isinstance(node, t.MemberReference) and not node.qualifier and not node.selectors:
            return env.get(node.member)
        if isinstance(node, t.ArrayInitializer):
            return BytesState("constant" if all(constant_element(v, env) for v in node.initializers) else "unknown", len(node.initializers), line(node))
        if isinstance(node, t.ArrayCreator) and name(node.type) == "byte":
            if node.initializer:
                return resolve(node.initializer, env)
            size = primitive(node.dimensions[0], env) if len(node.dimensions) == 1 else None
            return BytesState("constant" if isinstance(size, int) and size >= 0 else "unknown", size if isinstance(size, int) and size >= 0 else None, line(node))
        if isinstance(node, t.Literal) and node.selectors:
            selectors = node.selectors
            if len(selectors) == 1 and isinstance(selectors[0], t.MethodInvocation) and selectors[0].member == "getBytes":
                text = primitive(node, env)
                if isinstance(text, str):
                    return BytesState("constant", encoded_length(text, selectors[0].arguments, env), line(node), frozenset({text}))
            return None
        if isinstance(node, t.ClassCreator):
            kind = name(node.type)
            if kind in shadowed:
                return None
            if kind in {"SecureRandom", "Random"}:
                return Factory(kind)
            if kind == "String" and len(node.arguments) == 1:
                return primitive(node.arguments[0], env)
            if kind in {"SecretKeySpec", "IvParameterSpec", "GCMParameterSpec"}:
                has_materials = True
                if kind == "SecretKeySpec":
                    material = snapshot(resolve(node.arguments[0], env), node) if len(node.arguments) == 2 else BytesState("unknown", None, line(node))
                    algorithm = primitive(node.arguments[1], env) if len(node.arguments) == 2 else None
                    secret_strings.update(material.strings)
                    return Key(material, algorithm if isinstance(algorithm, str) else None)
                expected = 2 if kind == "GCMParameterSpec" else 1
                index = 1 if kind == "GCMParameterSpec" else 0
                material = snapshot(resolve(node.arguments[index], env), node) if len(node.arguments) == expected else BytesState("unknown", None, line(node))
                return Params(material, kind)
        if isinstance(node, t.MethodInvocation):
            qualifier = node.qualifier or ""
            short = qualifier.split(".")[-1]
            if node.member == "getInstance" and short in {"Cipher", "KeyGenerator", "SecureRandom"} and short not in shadowed:
                algorithm = primitive(node.arguments[0], env) if node.arguments else None
                return Factory(short, algorithm if isinstance(algorithm, str) else None)
            if node.member == "getInstanceStrong" and short == "SecureRandom" and short not in shadowed and not node.arguments:
                return Factory("SecureRandom")
            owner = env.get(qualifier)
            if node.member == "getBytes" and isinstance(owner, str):
                return BytesState("constant", encoded_length(owner, node.arguments, env), line(node), frozenset({owner}))
            if isinstance(owner, Factory) and owner.kind == "KeyGenerator" and node.member == "generateKey":
                return Key(BytesState("runtime", None, line(node)), owner.algorithm)
            if isinstance(owner, Factory) and owner.kind == "SecureRandom" and node.member == "generateSeed":
                size = primitive(node.arguments[0], env) if node.arguments else None
                return BytesState("runtime", size if isinstance(size, int) else None, line(node))
        return primitive(node, env)

    def finding(identifier, title, node, value, recommendation, reference, material_line=None, severity="high"):
        location = line(node)
        findings.append({"id": identifier, "kind": "material", "title": title, "severity": severity, "line": location, "materialOriginLine": material_line, "value": value, "evidence": lines[location - 1].strip() if location and location <= len(lines) else "Cipher.init(...) [material redactado]", "source": "deterministic_parameter_check", "recommendation": recommendation, "reference": reference, "redacted": True})

    def consume_init(node, env, cipher):
        if len(node.arguments) < 2:
            return
        base = cipher.algorithm.upper().split("/")[0] if isinstance(cipher.algorithm, str) else None
        if base is None:
            unknown(node, "No se resolvió la transformación para revisar la procedencia de clave e IV/nonce.")
            return
        if base not in {"AES", "DES", "DESEDE", "BLOWFISH", "RC2", "RC4"}:
            return  # This control concerns symmetric SecretKeySpec, not RSA keys.
        mode = primitive(node.arguments[0], env)
        key = resolve(node.arguments[1], env)
        params_observed = resolve(node.arguments[2], env) if len(node.arguments) >= 3 else None
        observations.append({
            "algorithm": cipher.algorithm, "operation": mode,
            "keyOrigin": key.material.origin if isinstance(key, Key) else "unknown",
            "keyLength": key.material.length if isinstance(key, Key) else None,
            "parameterKind": params_observed.kind if isinstance(params_observed, Params) else "unknown",
            "parameterOrigin": params_observed.material.origin if isinstance(params_observed, Params) else "unknown",
            "parameterLength": params_observed.material.length if isinstance(params_observed, Params) else None,
        })
        if mode not in {1, 2}:
            unknown(node, "Modo de inicialización Cipher no resuelto como cifrado o descifrado; no se infiere uso de IV.")
            return
        if isinstance(key, Key):
            material = key.material
            compatible = isinstance(key.algorithm, str) and base == key.algorithm.upper()
            invalid_aes_length = base == "AES" and material.length is not None and material.length not in {16, 24, 32}
            if not compatible:
                unknown(node, "No se comprobó que el algoritmo de SecretKeySpec coincida con el del cifrador.")
            elif invalid_aes_length:
                unknown(node, "Longitud del material AES no válida (se esperan 16, 24 o 32 bytes); revisar la configuración antes de evaluar su uso.")
            elif material.origin == "constant" and material.length != 0:
                finding("JAVA-EMBEDDED-KEY", "Posible clave simétrica incrustada usada en Cipher.init", node, "material de clave constante [redactado]", "Retirar la clave del código y de los artefactos distribuidos. Usar un almacén de claves o gestor de secretos y evaluar la rotación si estuvo expuesta.", "Procedencia local de material constante hacia SecretKeySpec y Cipher.init; no se publica la clave", material.line)
            elif material.origin == "unknown":
                unknown(node, "No se pudo determinar la procedencia del material de SecretKeySpec.")
            elif material.length == 0:
                unknown(node, "Material de clave vacío: revisar la validez de la configuración.")
        elif key is None:
            unknown(node, "No se resolvió la procedencia de la clave usada en Cipher.init; no se afirma que esté incrustada.")
        # An IV received with ciphertext may legitimately be fixed in a decryption
        # example. Only an encryption initialization triggers this control.
        if mode != 1 or not isinstance(cipher.algorithm, str):
            return
        parts = cipher.algorithm.upper().split("/")
        if len(parts) < 2 or parts[0] != "AES" or parts[1] not in {"CBC", "GCM"}:
            return
        if len(node.arguments) < 3:
            return  # Provider may generate parameters; do not assume a zero IV.
        params = resolve(node.arguments[2], env)
        expected = "GCMParameterSpec" if parts[1] == "GCM" else "IvParameterSpec"
        if not isinstance(params, Params) or params.kind != expected:
            unknown(node, "No se resolvieron los parámetros IV/nonce usados para cifrar.")
            return
        if parts[1] == "CBC" and params.material.length is not None and params.material.length != 16:
            unknown(node, "AES-CBC requiere un IV de 16 bytes; revisar la validez de los parámetros.")
        elif params.material.origin == "constant" and params.material.length != 0:
            gcm = parts[1] == "GCM"
            finding("JAVA-GCM-CONSTANT-NONCE" if gcm else "JAVA-CBC-CONSTANT-IV", "Nonce constante observado en cifrado AES-GCM" if gcm else "IV constante observado en cifrado AES-CBC", node, "nonce constante [redactado]" if gcm else "IV constante [redactado]", "Garantizar un nonce único para cada cifrado con la misma clave. Un valor fijo puede repetirse; este análisis no demuestra reutilización entre ejecuciones." if gcm else "Generar un IV nuevo e impredecible para cada cifrado CBC, y transportarlo junto al ciphertext. Evaluar cifrado autenticado cuando corresponda.", "Procedencia local de parámetros constantes hacia Cipher.init(ENCRYPT_MODE); no se afirma una explotación ni reutilización entre ejecuciones", params.material.line, severity="medium")
        elif params.material.origin == "unknown":
            unknown(node, "No se pudo determinar si el IV/nonce es constante o se genera en ejecución.")
        elif params.material.length == 0:
            unknown(node, "IV/nonce vacío: revisar la validez y longitud de parámetros.")

    def call(node, env):
        if isinstance(node, t.MemberReference) and node.selectors and (node.prefix_operators or node.postfix_operators):
            array = env.get(node.member)
            if isinstance(array, BytesState):
                array.origin = "unknown"
            return
        if isinstance(node, (t.MethodInvocation, t.ClassCreator)) and node.selectors:
            base_node = copy(node)
            base_node.selectors = []
            owner = resolve(base_node, env)
            for selector in node.selectors:
                if isinstance(selector, t.MethodInvocation):
                    if selector.member == "init" and isinstance(owner, Factory) and owner.kind == "Cipher":
                        consume_init(selector, env, owner)
                        owner = None
                        continue
                    for argument in selector.arguments:
                        array = resolve(argument, env)
                        if isinstance(array, BytesState):
                            array.origin = "runtime" if selector.member == "nextBytes" and isinstance(owner, Factory) and owner.kind == "SecureRandom" else "unknown"
                owner = None
            return
        if isinstance(node, t.ClassCreator):
            for argument in node.arguments:
                value = resolve(argument, env)
                if isinstance(value, BytesState):
                    value.origin = "unknown"
            return
        if not isinstance(node, t.MethodInvocation):
            return
        owner = env.get(node.qualifier)
        if isinstance(owner, Factory) and owner.kind == "Cipher" and node.member == "init":
            consume_init(node, env, owner)
            return
        if node.member == "nextBytes" and len(node.arguments) == 1:
            array = resolve(node.arguments[0], env)
            if isinstance(array, BytesState):
                array.origin = "runtime" if isinstance(owner, Factory) and owner.kind == "SecureRandom" else "unknown"
                array.strings = frozenset()
            return
        # A helper can modify a byte array even if we cannot inspect its body.
        for argument in node.arguments:
            array = resolve(argument, env)
            if isinstance(array, BytesState):
                array.origin = "unknown"

    def invalidate(node, env):
        for _, assignment in node.filter(t.Assignment):
            if isinstance(assignment.expressionl, t.MemberReference):
                target = env.get(assignment.expressionl.member)
                if assignment.expressionl.selectors and isinstance(target, BytesState):
                    target.origin = "unknown"
                else:
                    prior = env.get(assignment.expressionl.member)
                    env[assignment.expressionl.member] = Factory("Cipher") if isinstance(prior, Factory) and prior.kind == "Cipher" else None
        for _, invocation in node.filter(t.MethodInvocation):
            for argument in invocation.arguments:
                value = resolve(argument, env)
                if isinstance(value, BytesState):
                    value.origin = "unknown"

    def walk(body, env):
        for statement in body or []:
            if isinstance(statement, t.LocalVariableDeclaration):
                for declaration in statement.declarators:
                    value = resolve(declaration.initializer, env)
                    # Unknown helper calls may have mutated array arguments.
                    if isinstance(declaration.initializer, (t.MethodInvocation, t.ClassCreator)) and value is None:
                        call(declaration.initializer, env)
                    if isinstance(value, BytesState) and value.line is None:
                        value.line = line(statement)
                    if value is None and name(statement.type) == "Cipher" and "Cipher" not in shadowed:
                        value = Factory("Cipher")
                    env[declaration.name] = value
            elif isinstance(statement, t.StatementExpression):
                expr = statement.expression
                if isinstance(expr, t.Assignment) and isinstance(expr.expressionl, t.MemberReference) and not expr.expressionl.qualifier:
                    target = expr.expressionl
                    if target.selectors:
                        array = env.get(target.member)
                        if isinstance(array, BytesState) and (expr.type != "=" or not constant_element(expr.value, env)):
                            array.origin = "unknown"
                    else:
                        value = resolve(expr.value, env) if expr.type == "=" else None
                        if value is None and isinstance(expr.value, (t.MethodInvocation, t.ClassCreator)):
                            call(expr.value, env)
                        prior = env.get(target.member)
                        if value is None and isinstance(prior, Factory) and prior.kind == "Cipher":
                            value = Factory("Cipher")
                        env[target.member] = value
                else:
                    call(expr, env)
            elif isinstance(statement, t.BlockStatement):
                walk(statement.statements, dict(env))
                invalidate(statement, env)
            elif isinstance(statement, t.TryStatement):
                walk(statement.block, dict(env))
                invalidate(statement, env)
                if statement.finally_block:
                    walk(statement.finally_block, dict(env))
            elif isinstance(statement, (t.ReturnStatement, t.ThrowStatement)):
                break
            else:
                for _, invocation in statement.filter(t.MethodInvocation):
                    if invocation.member == "init" and isinstance(env.get(invocation.qualifier), Factory) and env[invocation.qualifier].kind == "Cipher":
                        unknown(invocation, "Inicialización bajo una rama o bucle no resuelto: revisar clave e IV/nonce manualmente.")
                invalidate(statement, env)

    for _, cls in unit.filter(t.ClassDeclaration):
        constants = {}
        for field in cls.fields:
            for declaration in field.declarators:
                value = resolve(declaration.initializer, constants) if {"static", "final"} <= field.modifiers else None
                # final byte[] does not make its contents immutable across methods.
                constants[declaration.name] = None if isinstance(value, BytesState) else value
                if value is None and name(field.type) == "Cipher" and "Cipher" not in shadowed:
                    constants[declaration.name] = Factory("Cipher")
        for method in cls.methods + cls.constructors:
            env = dict(constants)
            env.update({parameter.name: None for parameter in method.parameters})
            for parameter in method.parameters:
                if name(parameter.type) == "Cipher" and "Cipher" not in shadowed:
                    env[parameter.name] = Factory("Cipher")
            walk(method.body, env)
    return {"findings": findings, "unresolved": unresolved, "observations": observations, "_secret_strings": secret_strings, "_has_materials": has_materials}
