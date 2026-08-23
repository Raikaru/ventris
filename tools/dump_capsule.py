# Export one analyzed function as a stable, text-only Ghidra p-code capsule.
# Arguments: function name or entry address, output path.

args = list(getScriptArgs())
wanted = args[0] if len(args) > 0 else "FUN_140001460"
output_path = (
    args[1]
    if len(args) > 1
    else java.io.File(
        java.lang.System.getProperty("java.io.tmpdir"),
        "ventris/capsule/capsule.txt",
    ).getPath()
)

pick = None
functions = currentProgram.getFunctionManager().getFunctions(True)
for function in functions:
    match = function.getName() == wanted
    if not match:
        try:
            match = function.getEntryPoint().getOffset() == int(wanted, 0)
        except (TypeError, ValueError):
            pass
    if not function.isThunk() and not function.isExternal() and match:
        pick = function
        break

if pick is None:
    try:
        start = toAddr(wanted)
        disassemble(start)
        pick = createFunction(start, None)
    except Exception:
        pick = None

if pick is None:
    println("VENTRIS no candidate " + wanted)
else:
    entry = int(pick.getEntryPoint().getOffset())
    length = int(pick.getBody().getNumAddresses())
    memory = bytearray(length)
    currentProgram.getMemory().getBytes(pick.getEntryPoint(), memory)
    lines = [
        "function " + str(pick.getName()),
        "language " + str(currentProgram.getLanguage().getLanguageID()),
        "entry " + str(entry),
        "length " + str(length),
        "bytes " + bytes(memory).hex(),
    ]

    instructions = currentProgram.getListing().getInstructions(pick.getBody(), True)
    for instruction in instructions:
        operations = instruction.getPcode()
        lines.append(
            "inst {} {} {}  # {}".format(
                instruction.getAddress().getOffset(),
                instruction.getLength(),
                len(operations),
                instruction,
            )
        )
        for operation in operations:
            fields = ["  op " + str(operation.getOpcode())]
            output = operation.getOutput()
            if output is None:
                fields.append("void")
            else:
                address = output.getAddress()
                fields.append(
                    "{}:{}:{}".format(
                        address.getAddressSpace().getName(),
                        address.getOffset(),
                        output.getSize(),
                    )
                )
            for index in range(operation.getNumInputs()):
                input_node = operation.getInput(index)
                address = input_node.getAddress()
                fields.append(
                    "{}:{}:{}".format(
                        address.getAddressSpace().getName(),
                        address.getOffset(),
                        input_node.getSize(),
                    )
                )
            lines.append(" ".join(fields))

    language = currentProgram.getLanguage()
    for register in language.getRegisters():
        address = register.getAddress()
        lines.append(
            "reg {} {} {} {}".format(
                register.getName(),
                address.getAddressSpace().getName(),
                address.getOffset(),
                register.getMinimumByteSize(),
            )
        )
    for index in range(language.getNumberOfUserDefinedOpNames()):
        lines.append("userop {} {}".format(index, language.getUserDefinedOpName(index)))

    output = java.io.File(output_path)
    parent = output.getParentFile()
    if parent is not None:
        parent.mkdirs()
    with open(output_path, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    println(
        "VENTRIS capsule function={} entry={} len={} registers={} userops={}".format(
            pick.getName(), hex(entry), length, len(language.getRegisters()), language.getNumberOfUserDefinedOpNames()
        )
    )
    println("VENTRIS done")
