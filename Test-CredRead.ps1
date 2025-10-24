<#
.SYNOPSIS
    A minimal script to test reading a specific credential from the Windows Credential Manager.
    This script is self-contained and uses a C# helper to call the native Windows API.
    Its purpose is to diagnose if security policies are blocking this method of credential access.
#>

param()

# --- CONFIGURATION ---
# The exact target name of the credential to read, as shown by `cmdkey /list`.
$targetName = "LegacyGeneric:target=fwmgr"
# ---------------------

Write-Host "--- Starting Credential Read Test ---"
Write-Host "Attempting to read credential for target: '$targetName'"

# C# helper class to call the native Windows API function 'CredRead'.
# This is the core mechanism we are testing.
$cSharpSource = @"
using System;
using System.Runtime.InteropServices;
using System.Management.Automation;

public static class CredentialHelper {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int flags, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static PSCredential GetCredential(string target) {
        IntPtr credPtr;
        if (!CredRead(target, 1, 0, out credPtr)) { // Type 1 = Generic Credential
            return null;
        }

        try {
            var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            var password = Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
            return new PSCredential(cred.UserName, (new System.Net.NetworkCredential(string.Empty, password)).SecurePassword);
        }
        finally {
            CredFree(credPtr);
        }
    }
}
"@

# Step 1: Try to compile the C# helper code in memory.
Write-Host "Step 1: Compiling C# helper..."
try {
    Add-Type -TypeDefinition $cSharpSource -Language CSharp
    Write-Host "Step 1 SUCCESS: C# helper compiled successfully." -ForegroundColor Green
} catch {
    Write-Host "Step 1 FAILURE: Failed to compile the C# helper." -ForegroundColor Red
    Write-Host "This is a strong indicator that a security policy (like AppLocker) is blocking in-memory code compilation." -ForegroundColor Yellow
    Write-Host "Error details: $_"
    Write-Host "--- Test Finished ---"
    # Exit the script if compilation fails.
    return
}

# Step 2: Try to use the compiled helper to read the credential.
Write-Host "`nStep 2: Calling the helper to read the credential..."
$credential = $null
try {
    $credential = [CredentialHelper]::GetCredential($targetName)
} catch {
    Write-Host "Step 2 FAILURE: An exception occurred while calling the credential helper." -ForegroundColor Red
    Write-Host "Error details: $_"
    Write-Host "--- Test Finished ---"
    # Exit the script on error.
    return
}

# Step 3: Report the final result.
Write-Host "`nStep 3: Analyzing results..."
if ($credential) {
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host " OVERALL RESULT: SUCCESS!" -ForegroundColor Green
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Successfully found and read the credential."
    Write-Host "Username: $($credential.UserName)"

    # For absolute proof, we will display the password.
    Write-Host "`nWARNING: The following is the plain-text password, shown for debugging purposes only." -ForegroundColor Yellow
    $plainTextPassword = $credential.GetNetworkCredential().Password
    Write-Host "Password: $plainTextPassword"
} else {
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host " OVERALL RESULT: FAILURE!" -ForegroundColor Red
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "The script compiled correctly, but could not find or read the credential for '$targetName'."
    Write-Host "This confirms that access to the credential store via this method is being blocked by the system."
}

Write-Host "`n--- Test Finished ---"
