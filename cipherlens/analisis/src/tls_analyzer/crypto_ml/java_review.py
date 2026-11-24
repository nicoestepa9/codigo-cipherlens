"""Bounded Java AST review: explicit local parameters, never Java execution.

Only straight-line local assignments and immutable class constants are resolved.
Conditional, loop and interprocedural values produce an explicit abstention.
"""
from __future__ import annotations

import re


def inspect_java(source: str) -> dict:
    import javalang
    from javalang import tree as t

    if re.search(r"\\u+[0-9a-fA-F]{4}", source):
        return {"facts": [], "findings": [], "unresolved": [{"line": None, "reason": "Los escapes Unicode de Java requieren revisión manual para preservar ubicaciones y semántica."}], "parsed": False}
    try:
        unit = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError, RecursionError):
        return {"facts": [], "findings": [], "unresolved": [{"line": None, "reason": "No se pudo interpretar el archivo como Java 8; no se ejecutó."}], "parsed": False}
    lines = source.splitlines()
    facts, findings, unresolved = [], [], []
    shadowed_types = {node.name for _, node in unit.filter(t.ClassDeclaration)}
    setter_methods, mutable_fields = {}, set()
    class_name = ""
    trace_entry = False

    def short_type(node):
        while getattr(node, "sub_type", None):
            node = node.sub_type
        return getattr(node, "name", "")

    def line_of(node):
        return node.position.line if getattr(node, "position", None) else None

    def scalar(node, env):
        if isinstance(node, t.Literal):
            raw = node.value
            if node.prefix_operators or node.postfix_operators:
                return None
            if raw.startswith('"') and raw.endswith('"') and "\\" not in raw:
                return raw[1:-1]
            if re.fullmatch(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)", raw):
                value = raw.replace("_", "")
                try:
                    number = int(value, 16 if value.lower().startswith("0x") else 2 if value.lower().startswith("0b") else 8 if len(value) > 1 and value.startswith("0") else 10)
                    return number if number <= 2**31 - 1 else None
                except ValueError:
                    return None
        if isinstance(node, t.MemberReference) and not node.qualifier and not node.prefix_operators and not node.postfix_operators:
            return env.get(node.member)
        return None

    def unknown(node, reason):
        unresolved.append({"line": line_of(node), "reason": reason})

    def fact(kind, value, node, receiver):
        line = line_of(node)
        item = {"kind": kind, "value": value, "line": line, "receiver": receiver, "evidence": lines[line - 1].strip() if line and line <= len(lines) else "", "source": "deterministic_parameter_check"}
        facts.append(item)
        rule = None
        if kind == "rsa_bits" and isinstance(value, int) and value < 2048:
            rule = ("JAVA-RSA-SIZE", "Tamaño RSA inferior a 2048 bits", "high", "Usar al menos 2048 bits para nuevas claves RSA; seleccionar el tamaño según la política y duración de protección.", "NIST SP 800-131A Rev.2, generación de firmas RSA; este control comprueba solo el tamaño declarado")
        if kind == "cipher" and isinstance(value, str):
            parts = value.upper().split("/")
            if parts[0] == "AES" and len(parts) >= 2 and parts[1] == "ECB":
                rule = ("JAVA-AES-ECB", "AES configurado explícitamente en modo ECB", "high", "Evitar ECB para datos de aplicación. Evaluar AES-GCM con nonce único por clave y gestión correcta de la etiqueta de autenticación.", "Control de revisión de uso de AES-ECB; no evalúa contenido, tamaño del mensaje ni gestión de nonces")
            elif parts[0] == "RSA" and len(parts) >= 3 and parts[-1] == "NOPADDING":
                rule = ("JAVA-RSA-NOPADDING", "RSA configurado sin padding", "high", "No usar RSA sin padding para cifrar datos de aplicación; usar un esquema aprobado como RSA-OAEP con parámetros explícitos y adecuados al contexto.", "Control de revisión de transformación RSA/…/NoPadding")
            elif parts[0] in {"AES", "RSA"} and len(parts) == 1:
                rule = ("JAVA-CIPHER-IMPLICIT-DEFAULTS", "Transformación incompleta: modo y padding implícitos", "medium", "Declarar explícitamente algoritmo, modo y padding adecuados al uso. El nombre del algoritmo solo no permite conocer los valores que elegirá el proveedor.", "Java Cipher.getInstance: los valores predeterminados de modo y padding dependen del proveedor; no se afirma que sean ECB")
        if rule:
            identifier, title, severity, recommendation, reference = rule
            findings.append({**item, "id": identifier, "title": title, "severity": severity, "recommendation": recommendation, "reference": reference})

    def factory(node, env):
        if isinstance(node, t.MethodInvocation) and node.member == "getInstance" and node.qualifier.split(".")[-1] in {"Cipher", "KeyPairGenerator", "KeyGenerator"} and len(node.arguments) == 1:
            if "." not in node.qualifier and node.qualifier in shadowed_types:
                return None
            return node.qualifier.split(".")[-1], scalar(node.arguments[0], env)
        return None

    def relevant(node, holders):
        return isinstance(node, t.MethodInvocation) and ((node.member == "getInstance" and node.qualifier.split(".")[-1] in {"Cipher", "KeyPairGenerator", "KeyGenerator"}) or (node.member == "initialize" and node.qualifier in holders))

    def expression(node, env, holders):
        created = factory(node, env)
        if created and created[0] == "Cipher":
            if isinstance(created[1], str):
                fact("cipher", created[1], node, node.qualifier)
            else:
                unknown(node, "Transformación Cipher indirecta o fuera del ámbito local soportado.")
        elif isinstance(node, t.MethodInvocation) and node.member == "initialize" and node.qualifier in holders:
            kind, algorithm = holders[node.qualifier]
            if kind == "KeyPairGenerator" and algorithm == "RSA":
                value = scalar(node.arguments[0], env) if node.arguments else None
                if isinstance(value, int) and value > 0:
                    fact("rsa_bits", value, node, node.qualifier)
                else:
                    unknown(node, "No se resolvió el tamaño RSA a un entero local inequívoco.")
            elif kind == "KeyPairGenerator" and algorithm is None:
                unknown(node, "No se resolvió el algoritmo del generador; no se infiere que sea RSA.")

    def statements(body, env, holders):
        for statement in body or []:
            if isinstance(statement, t.LocalVariableDeclaration):
                for declaration in statement.declarators:
                    expression(declaration.initializer, env, holders)
                    env[declaration.name] = scalar(declaration.initializer, env)
                    # A declaration shadows a receiver from an enclosing block.
                    holders.pop(declaration.name, None)
                    created = factory(declaration.initializer, env)
                    declared_type = short_type(statement.type)
                    if created and created[0] == declared_type:
                        holders[declaration.name] = created
            elif isinstance(statement, t.StatementExpression):
                node = statement.expression
                if trace_entry and isinstance(node, t.MethodInvocation) and node.qualifier in {"", class_name} and node.member in setter_methods:
                    setter = setter_methods[node.member]
                    if not node.arguments and setter is not None:
                        for assignment in setter:
                            env[assignment.expressionl.member] = scalar(assignment.value, env)
                    else:
                        for field in mutable_fields:
                            env[field] = None
                    continue
                if isinstance(node, t.Assignment) and isinstance(node.expressionl, t.MemberReference) and not node.expressionl.qualifier:
                    name = node.expressionl.member
                    expression(node.value, env, holders)
                    env[name] = scalar(node.value, env) if node.type == "=" else None
                    created = factory(node.value, env)
                    if name in holders:
                        if created and created[0] == holders[name][0]:
                            holders[name] = created
                        else:
                            holders.pop(name, None)
                else:
                    if isinstance(node, t.MemberReference) and (node.prefix_operators or node.postfix_operators):
                        env[node.member] = None
                    expression(node, env, holders)
                    if trace_entry and isinstance(node, t.MethodInvocation) and factory(node, env) is None and not (node.member == "initialize" and node.qualifier in holders):
                        for field in mutable_fields:
                            env[field] = None
            elif isinstance(statement, t.BlockStatement):
                # Conservative: don't leak inner declarations/assignments out.
                statements(statement.statements, dict(env), dict(holders))
                for _, assignment in statement.filter(t.Assignment):
                    if isinstance(assignment.expressionl, t.MemberReference):
                        env[assignment.expressionl.member] = None
                        holders.pop(assignment.expressionl.member, None)
            elif isinstance(statement, t.ReturnStatement):
                expression(statement.expression, env, holders)
                break
            elif isinstance(statement, t.ThrowStatement):
                break
            elif isinstance(statement, t.TryStatement):
                statements(statement.block, dict(env), dict(holders))
                for handler in statement.catches or []:
                    for _, call in handler.filter(t.MethodInvocation):
                        if relevant(call, holders):
                            unknown(call, "Llamada en manejo de excepciones; revisar su contexto.")
                for _, assignment in statement.filter(t.Assignment):
                    if isinstance(assignment.expressionl, t.MemberReference):
                        env[assignment.expressionl.member] = None
                        holders.pop(assignment.expressionl.member, None)
                if statement.finally_block:
                    statements(statement.finally_block, dict(env), dict(holders))
            else:
                # No branch selection, exception modelling or loop execution.
                for _, call in statement.filter(t.MethodInvocation):
                    if relevant(call, holders):
                        unknown(call, "Llamada bajo una estructura de control no resuelta; revisar manualmente.")
                for _, assignment in statement.filter(t.Assignment):
                    if isinstance(assignment.expressionl, t.MemberReference):
                        env[assignment.expressionl.member] = None
                        holders.pop(assignment.expressionl.member, None)

    for _, cls in unit.filter(t.ClassDeclaration):
        class_name = cls.name
        constants = {}
        mutable_fields = set()
        for field in cls.fields:
            for declaration in field.declarators:
                constants[declaration.name] = scalar(declaration.initializer, constants) if {"static", "final"} <= field.modifiers else None
                if "static" in field.modifiers and "final" not in field.modifiers:
                    mutable_fields.add(declaration.name)
        # Only summarize argument-free static methods made exclusively of simple
        # assignments to this class's mutable static fields. Never invoke Java.
        setter_methods = {}
        for method in cls.methods:
            if method.name in setter_methods:
                setter_methods[method.name] = None
                continue
            assignments = []
            eligible = "static" in method.modifiers and not method.parameters and method.return_type is None and bool(method.body)
            for statement in method.body or []:
                node = statement.expression if isinstance(statement, t.StatementExpression) else None
                if not (isinstance(node, t.Assignment) and node.type == "=" and isinstance(node.expressionl, t.MemberReference) and not node.expressionl.qualifier and node.expressionl.member in mutable_fields and isinstance(node.value, (t.Literal, t.MemberReference))):
                    eligible = False
                else:
                    assignments.append(node)
            setter_methods[method.name] = assignments if eligible else None
        for method in cls.methods + cls.constructors:
            env = dict(constants)
            for parameter in method.parameters:
                env[parameter.name] = None
            local_names = {d.name for _, declaration in method.filter(t.LocalVariableDeclaration) for d in declaration.declarators}
            trace_entry = method.name == "main" and "static" in method.modifiers and not (local_names & set(constants)) and not any(isinstance(member, list) for member in cls.body)
            statements(method.body, env, {})
    from .material_review import inspect_materials
    from .experiment import TOKEN
    material_result = inspect_materials(unit, source)
    findings.extend(material_result["findings"])
    unresolved.extend(material_result["unresolved"])
    sensitive_strings = material_result["_secret_strings"]
    if material_result["_has_materials"]:
        for item in facts + findings:
            # Evidence may share a physical line with a secret declaration.
            # Redact literals/comments from that evidence, never return key bytes.
            evidence = item.get("evidence", "")
            pieces, end = [], 0
            for match in TOKEN.finditer(evidence):
                pieces.append(evidence[end:match.start()])
                token = match.group()
                if token.startswith(("//", "/*")):
                    token = "[comentario omitido]"
                elif token.startswith(('"', "'")) or token[0].isdigit():
                    token = "[literal redactado]"
                pieces.append(token)
                end = match.end()
            pieces.append(evidence[end:])
            redacted = "".join(pieces)
            # A block comment may continue beyond this single evidence line.
            for marker in ("/*", "//"):
                if marker in redacted:
                    redacted = redacted.split(marker, 1)[0] + "[comentario omitido]"
            for secret in sensitive_strings:
                if secret:
                    redacted = redacted.replace(secret, "[material redactado]")
            item["evidence"] = redacted
            item["redacted"] = True
            if isinstance(item.get("value"), str) and item["value"] in sensitive_strings:
                item["value"] = "[material redactado]"
    unique_unknown = []
    seen_unknown = set()
    for item in unresolved:
        key = (item["line"], item["reason"])
        if key not in seen_unknown:
            seen_unknown.add(key)
            unique_unknown.append(item)
    return {"facts": facts, "findings": findings, "unresolved": unique_unknown, "parsed": True}
