import subprocess
import argparse
import os
import sys
import re
import pefile

# Common instructions for query I/O communications port, red pill, and no pill
ANTI_VM_INSTRUCTIONS = {'in', 'rdtsc', 'sgdt', 'sldt', 'sidt'}
# If malware is doing a timing check
GTC_NAMES = [b"GetTickCount", b"GetTickCount64"]
GTC_TARGET_DLLS = [b"kernel32.dll", b"api-ms-win-core-sysinfo-"]
SCM_DLL_NAMES = [b"kernel32.dll", b"advapi32.dll"]
# VMWare indicators
VMWARE_STRINGS = [b"vmtools", b"vmware", b"vmware-usbarbitrator", b"vmware-converter"]
# If malware is scanning the process listing with functions like CreateToolhelp32Snapshot , Process32Next , and so on.
PROCESS_ENUM_NAMES = [b"CreateToolhelp32Snapshot",b"Process32First", b"Process32FirstW",b"Process32Next", b"Process32NextW"]
# More enumeration indicators from my malware
SCM_API_NAMES = [b"OpenSCManagerA", b"OpenSCManagerW", b"OpenServiceA", b"OpenServiceW",b"EnumServicesStatusExA", b"EnumServicesStatusExW", b"QueryServiceStatusEx",b"EnumDependentServicesA", b"EnumDependentServicesW"]
PROCESS_ENUM_TARGET_DLLS = [b"kernel32.dll"]

def check_gettickcount(file_path):
    """Checks for GetTickCount/GetTickCount64 usage."""
    findings = []
    file_basename = os.path.basename(file_path)
    print(f"... GetTickCount Check: Starting analysis for '{file_basename}'...")

    try:
        print(f"... GetTickCount Check: Searching for strings...")
        with open(file_path, 'rb') as f: file_content = f.read()
        for name_bytes in GTC_NAMES:
            if name_bytes in file_content:
                func_name = name_bytes.decode(errors='ignore')
                finding_tuple = ("String Found", func_name)
                if finding_tuple not in findings:
                    findings.append(finding_tuple)
    except Exception as e:
        print(f"ERROR ON check_gettickcount(): {e}", file=sys.stderr)

    if not findings:
        print("... GetTickCount Check: No indicators found.")
    return findings

def check_vmware_service_query(file_path):
    """Checks for potential VMware service query anti-VM technique."""
    found_api_strings = set()
    found_vmware_strings = set()
    file_content = None
    file_basename = os.path.basename(file_path)
    print(f"... VMware Check: Starting analysis for '{file_basename}'...")

    # Read file content
    try:
        with open(file_path, 'rb') as f: file_content = f.read()
    except Exception as e:
        print(f"ERROR ON check_vmware_service_query(): '{file_basename}': {e}", file=sys.stderr)
        return None, None, None

    # Check for SCM API Name Strings
    print(f"... VMware Check: Searching for SCM API name strings...")
    for api_name_bytes in SCM_API_NAMES:
        if api_name_bytes in file_content: found_api_strings.add(api_name_bytes.decode(errors='ignore'))
    for dll_name_bytes in SCM_DLL_NAMES:
        if dll_name_bytes in file_content: found_api_strings.add(dll_name_bytes.decode(errors='ignore') + " (DLL Name)")

    # Check for VMware Strings
    print(f"... VMware Check: Searching for VMware-related strings...")
    file_content_lower = file_content.lower()
    for vm_str_bytes in VMWARE_STRINGS:
        if vm_str_bytes.lower() in file_content_lower:
            found_vmware_strings.add(vm_str_bytes.decode(errors='ignore'))

    if not found_api_strings and not found_vmware_strings:
         print("... VMware Check: No indicators found.")

    return found_api_strings, found_vmware_strings

def check_process_enumeration(file_path):
    """Checks for Toolhelp32 process enumeration functions."""
    findings = []
    file_basename = os.path.basename(file_path)
    print(f"... Process Enum Check: Starting analysis for '{file_basename}'...")

    try:
        print(f"... Process Enum Check: Searching for Toolhelp32 API strings...")
        with open(file_path, 'rb') as f: file_content = f.read()
        for name_bytes in PROCESS_ENUM_NAMES:
            if name_bytes in file_content:
                func_name = name_bytes.decode(errors='ignore')
                finding_tuple = ("String Found", func_name)
                if finding_tuple not in findings:
                    findings.append(finding_tuple)
    except Exception as e:
        print(f"ERROR ON check_process_enumeration(): {e}", file=sys.stderr)

    if not findings:
        print("... Process Enum Check: No indicators found.")
    return findings

def run_objdump(file_path):
    """Runs 'objdump -d' in order to be able to analyze the instructions easily."""
    file_basename = os.path.basename(file_path)
    print(f"... Objdump Check: Starting analysis for '{file_basename}'...")
    if not os.path.exists(file_path):
        print(f"NO FILE FOUND: {file_path}", file=sys.stderr); return None, True

    command = ['objdump', '-d', file_path]
    print(f"... Objdump Check: Running command: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, errors='ignore')
        print("... Objdump Check: Disassembly obtained.")
        return result.stdout, False
    except Exception as e:
        print(f"ERROR ON run_objdump(): '{file_basename}': {e}", file=sys.stderr); return None, True

def analyze_objdump_output(objdump_output, target_instructions):
    """Parses objdump output for target instructions, and then just return the set of found instructions."""
    if not objdump_output: return set()

    found_instructions = set()
    lines = objdump_output.splitlines()
    pattern = re.compile(r'[\s\t]((' + '|'.join(re.escape(inst) for inst in target_instructions) + r'))($|[\s\t])')
    print(f"... Objdump Check: Analyzing disassembly for: {', '.join(sorted(target_instructions))}")

    for i, line in enumerate(lines):
        if ':' not in line: continue
        match = pattern.search(line)
        if match:
            instruction_found = match.group(1)
            found_instructions.add(instruction_found)
            print(f"... Found instruction '{instruction_found}' at line {i + 1}: {line.strip()}")

    if not found_instructions:
        print("... Objdump Check: No target Vulnerable anti-VM instructions found.")
    return found_instructions

if __name__ == "__main__":
    # Setup arguments to for the anti anti-vm checker
    parser = argparse.ArgumentParser()
    parser.add_argument("file_path")
    args = parser.parse_args()
    file_path = args.file_path
    file_basename = os.path.basename(file_path)

    # Begin checking anti-vm techniques from Chapter 17 & my malware
    print(f"=== Starting analysis for: {file_path} ===")

    print("(1) Performing GetTickCount Check...")
    gtc_findings = check_gettickcount(file_path)

    print("\n(2) Performing VMware Service Query Check...")
    apis_string, vm_strings = check_vmware_service_query(file_path)

    print("\n(3) Performing Process Enumeration Check...")
    proc_enum_findings = check_process_enumeration(file_path)

    print("\n(4) Performing Vulnerable Instruction Check (Objdump)...")
    objdump_text, objdump_error = run_objdump(file_path)
    found_instructions = analyze_objdump_output(objdump_text, ANTI_VM_INSTRUCTIONS)

    # Results Section
    print(f"\n=== Analysis Results Summary for '{file_basename}' ===")

    analysis_performed = True
    found_indicators = False

    # GetTickCount Results
    if gtc_findings:
        found_indicators = True
        print("[1] GetTickCount / Timing Check:")
        for find_type, func_name in gtc_findings:
            print(f"  - Found '{func_name}'")
            print("    Interpretation: Malware will simply execute this instruction twice and compare the difference between the two readings")
            print("                    to detect VMs and debuggers, which execute the code much more slowly.")
            print("    Recommendation: You can avoid detection by setting a breakpoint right after this check.")
            print("    Recommendation: OR, you can modify any time comparison conditionals to force the jump that you want.")
    # VMware Service Query Results
    if vm_strings is None:
        analysis_performed = False
        print("what")
    else:
        scm_evidence_found = bool(apis_string)
        vmware_evidence_found = bool(vm_strings)
        if scm_evidence_found or vmware_evidence_found:
            found_indicators = True
            print("[2] VMware Service Query Check:")
            if apis_string: print("  - Found SCM API/DLL strings:", sorted(apis_string))
            if vm_strings: print("  - Found VMware-related strings:", sorted(vm_strings))

            if scm_evidence_found and vmware_evidence_found:
                print("    Interpretation: The malware is very likely enumerating the services running that are unique to the VM, and then terminating if so")
                print("    Recommendation: Confirm behavior via dynamic analysis in VMware. Check which service names are queried.")
                print("                    You could then patch out the conditionals that check for the services.")
            elif scm_evidence_found:
                print("    Interpretation: The malware is potentially enumerating the services running that are unique to the VM, and then terminating if so")
                print("    Recommendation: Investigate which services are queried during dynamic analysis.")
                print("                    You could then patch out the conditionals that check for the services.")
            elif vmware_evidence_found:
                print("    Interpretation: The malware is potentially checking for characteristics that are unique to the VM, and then terminating if so")
                print("    Recommendation: Determine if the malware is doing any checks with the strings, and then patch out any conditionals")

    # Process Enumeration Results
    if proc_enum_findings:
        found_indicators = True
        print("[3] Process Enumeration Check:")
        for find_type, func_name in proc_enum_findings:
            print(f"  - Found '{func_name}'")
        print("    Interpretation: Use of Toolhelp32 functions (CreateToolhelp32Snapshot, Process32First/Next)")
        print("                    indicates the malware enumerates running processes to check for VMWare artifacts.")
        print("    Recommendation: Perform static or dynamic analysis to see which process names it compares against.")
        print("                    Then, you can patch it to avoid detection by forcing conditionals you need.")

    # Vulnerable Instruction Results
    if objdump_error and not found_instructions:
        print("objdump error")
    elif found_instructions:
        found_indicators = True
        print("[4] Vulnerable Instruction Check:")
        if 'sidt' in found_instructions:
            print("  - Found 'sidt' instruction.")
            print("    Interpretation: This is the 'Red Pill' Anti-VM technique.")
            print("                    This checks the location of the Interrupt Descriptor Table Register (IDTR).")
            print("                    VM monitors relocate the guest's IDTR, and 'sidt' returns the guest's relocated value, differing")
            print("                    from the expected host value, revealing to the malware it was in a simulation (VM).")
            print("    Recommendation: Run the malware on a multicore processor, or just NOP out the sidt instruction")
        if 'sldt' in found_instructions or 'sgdt' in found_instructions:
            instr = "'sldt'" if 'sldt' in found_instructions else "'sgdt'"
            if 'sldt' in found_instructions and 'sgdt' in found_instructions: instr = "'sldt'/'sgdt'"
            print(f"  - Found {instr} instruction(s).")
            print("    Interpretation: This is the 'No Pill' Anti-VM technique.")
            print("                    'sldt' checks the Local Descriptor Table (LDT) location. VMware provides virtual")
            print("                    LDT support (non-zero location), while Windows often doesn't use it (zero location).")
            print("                    'sgdt' checks the Global Descriptor Table location, which might also differ.")
            print("    Recommendation: Disabling acceleration in VirtualBox can subvert sldt.")
            print("                    Additionally, you could patch it out by forcing the conditional to take the jump you want.")
        if 'in' in found_instructions:
            print("  - Found 'in' instruction.")
            print("    Interpretation: The malware is communicating with the hypervisor via a special I/O port (0x5658 or 'VX').")
            print("                    Typically requires specific values in EAX (e.g., magic number 0x564D5868 'VMXh')")
            print("                    and ECX (e.g., 0xA for version(more popular), 0x14 for memory size).")
            print("    Recommendation: Analyze code around the 'in' instruction. Check register values (EAX, ECX, DX)")
            print("                    before the call. Look for the magic numbers 'VX' or 'VMXh' nearby.")
            print("                    After confirming this Anti-VM check, you should NOP out the 'in' instruction.")
        if 'rdtsc' in found_instructions:
            print("  - Found 'rdtsc' instruction.")
            print("    Interpretation: Malware will simply execute this instruction twice and compare the difference between the two readings")
            print("                    to detect VMs and debuggers, which execute the code much more slowly.")
            print("    Recommendation: You can avoid detection by setting a breakpoint right after this check.")
            print("    Recommendation: OR, you can modify the conditional to force the jump that you want.")