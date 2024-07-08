using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
//using System.Security.Principal;

namespace SeIncreaseQuotaPrivilege
{

    class SeIncreaseTokenPriviledge
    {
        // https://github.com/poweradminllc/PAExec/blob/master/Process.cpp
        static string ListOfPrivileges = "SeCreateTokenPrivilege,SeAssignPrimaryTokenPrivilege,SeLockMemoryPrivilege,SeIncreaseQuotaPrivilege,SeMachineAccountPrivilege," +
                            "SeTcbPrivilege,SeSecurityPrivilege,SeTakeOwnershipPrivilege,SeLoadDriverPrivilege,SeSystemProfilePrivilege,SeSystemtimePrivilege,SeProfileSingleProcessPrivilege," +
                            "SeIncreaseBasePriorityPrivilege,SeCreatePagefilePrivilege,SeCreatePermanentPrivilege,SeBackupPrivilege,SeRestorePrivilege,SeShutdownPrivilege,SeDebugPrivilege," +
                            "SeAuditPrivilege,SeSystemEnvironmentPrivilege,SeChangeNotifyPrivilege,SeRemoteShutdownPrivilege,SeUndockPrivilege,SeSyncAgentPrivilege,SeEnableDelegationPrivilege," +
                            "SeManageVolumePrivilege,SeImpersonatePrivilege,SeCreateGlobalPrivilege,SeTrustedCredManAccessPrivilege,SeRelabelPrivilege,SeIncreaseWorkingSetPrivilege," +
                            "SeTimeZonePrivilege,SeCreateSymbolicLinkPrivilege";
        //https://stackoverflow.com/questions/11169431/how-to-start-a-new-process-without-administrator-privileges-from-a-process-with

        public static void Main() // 
        {
            string fileName = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"Get-Process | Out-File - FilePath \"\"c:\\temp\\process.txt\"\"\" ";
            Console.WriteLine("Select Temp or Docs or Cmd");
            string location = Console.ReadLine();
            if (String.IsNullOrEmpty(location))
            {
                Console.WriteLine("Error in readline.");
            }
            if (location.Equals("Temp", StringComparison.CurrentCultureIgnoreCase))
            {
                fileName = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"Get-Process | Out-File - FilePath \"\"c:\\temp\\process.txt\"\"\" ";
            }
            if (location.Equals("Docs", StringComparison.CurrentCultureIgnoreCase))
            {
                fileName = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"Get-Process | Out-File - FilePath \"\"c:\\Users\\talle\\Documents\\process.txt\"\"\" ";
            }
            if (location.Equals("Cmd", StringComparison.CurrentCultureIgnoreCase))
            {
                fileName = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"Get-Process\" ";
            }
            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(fileName));

            // To start process as shell user you will need to carry out these steps:
            // 1. Enable the SeIncreaseQuotaPrivilege in your current token
            // 2. Get an HWND representing the desktop shell (GetShellWindow)
            // 3. Get the Process ID(PID) of the process associated with that window(GetWindowThreadProcessId)
            // 4. Open that process(OpenProcess)
            // 5. Get the access token from that process (OpenProcessToken)
            // 6. Make a primary token with that token(DuplicateTokenEx)
            // 7. Start the new process with that primary token(CreateProcessWithTokenW)
            //foreach (String Priv in ListOfPrivileges.Split("'"))
            //{
                long foo = grantprivilege.LsaUtility.AddRight(Environment.UserName, "SeIncreaseQuotaPrivilege");
            //}
            var hProcessToken = IntPtr.Zero;
            // Enable SeIncreaseQuotaPrivilege in this process.  (This won't work if current process is not elevated.)
            try
            {
                var process = GetCurrentProcess();
                if (!OpenProcessToken(process, 0x0020, ref hProcessToken))
                    return;
                //uint tkpsize = 1;
                //tkpsize = (uint)(ListOfPrivileges.Split(",").Length);
                var tkp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = (uint)(ListOfPrivileges.Split(",").Length),
                    Privileges = new LUID_AND_ATTRIBUTES[(uint)(ListOfPrivileges.Split(",").Length)]
                };
                int i = 0;
                foreach (string tkpName in ListOfPrivileges.Split(","))
                {
                    if (!LookupPrivilegeValue(null, tkpName, ref tkp.Privileges[i].Luid))
                        return;
                    tkp.Privileges[i++].Attributes = 0x00000002;
                }

                if (!AdjustTokenPrivileges(hProcessToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero))
                    return;
                //int tkInfoLength = 0;
                int nLastWin32Error = Marshal.GetLastWin32Error();
                //TokenInformationClass TemporaryStorageForTokenInformation = new TokenInformationClass();
                //GetTokenInformation(hProcessToken, ref TemporaryStorageForTokenInformation, IntPtr.Zero, ref tkInfoLength, ref tkInfoLength);
                //int nLastWin32Error = Marshal.GetLastWin32Error();
                //TOKEN_PRIVILEGES TemporaryStorageForTokenPrivileges = TemporaryStorageForTokenInformation.TokenPrivileges;
                //GetTokenInformation(hToken, TokenInformationClass.TokenPrivileges, IntPtr.Zero, tkInfoLength, tkInfoLength)
            }
            catch
            {
                Console.WriteLine("Elevation Error.");
            }
            finally
            {
                CloseHandle(hProcessToken);
            }

            // Get an HWND representing the desktop shell.
            // CAVEATS:  This will fail if the shell is not running (crashed or terminated), or the default shell has been
            // replaced with a custom shell.  This also won't return what you probably want if Explorer has been terminated and
            // restarted elevated.
            var hwnd = GetShellWindow();
            if (hwnd == IntPtr.Zero)
                return;

            var hShellProcess = IntPtr.Zero;
            var hShellProcessToken = IntPtr.Zero;
            var hPrimaryToken = IntPtr.Zero;
            try
            {
                // Get the PID of the desktop shell process.
                uint dwPID;
                if (GetWindowThreadProcessId(hwnd, out dwPID) == 0)
                    return;

                // Open the desktop shell process in order to query it (get the token)
                hShellProcess = OpenProcess(ProcessAccessFlags.QueryInformation, false, dwPID);
                if (hShellProcess == IntPtr.Zero)
                    return;

                // Get the process token of the desktop shell.
                if (!OpenProcessToken(hShellProcess, 0x0002, ref hShellProcessToken))
                    return;

                var dwTokenRights = 395U;

                // Duplicate the shell's process token to get a primary token.
                // Based on experimentation, this is the minimal set of rights required for CreateProcessWithTokenW (contrary to current documentation).
                if (!DuplicateTokenEx(hShellProcessToken, dwTokenRights, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hPrimaryToken))
                    return;

                // Start the target process with the new token.
                var si = new STARTUPINFO();
                var pi = new PROCESS_INFORMATION();
                if (!CreateProcessWithTokenW(hPrimaryToken, 0, fileName, "", 0, IntPtr.Zero, Path.GetDirectoryName(fileName), ref si, out pi))
                    return;
            }
            finally
            {
                CloseHandle(hShellProcessToken);
                CloseHandle(hPrimaryToken);
                CloseHandle(hShellProcess);
            }

        }

        #region Interop

        private struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string host, string name, ref LUID pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TOKEN_PRIVILEGES newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);


        [DllImport("user32.dll")]
        private static extern IntPtr GetShellWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, uint processId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL impersonationLevel, TOKEN_TYPE tokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671%28v=vs.85%29.aspx
        [DllImport("Advapi32.dll", SetLastError = true)]
        private static extern Boolean GetTokenInformation(IntPtr tokenHandle,
                                                   ref TokenInformationClass tokenInformationClass,
                                                   IntPtr tokenInformation,
                                                   ref int tokenInformationLength,
                                                   ref int refReturnLength
        );[return: MarshalAs(UnmanagedType.Bool)]
        private enum TokenInformationClass
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            TokenIsAppSilo,
            TokenLoggingInformation,
            MaxTokenInfoClass
        }

        #endregion
    }
}
//https://github.com/DmytroGerasymchuk/grantprivilege/blob/master/src/raw/LsaUtility.cs

namespace grantprivilege
{

    public class LsaUtility
    {

        // LSA functions

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern UInt32 LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            Int32 DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern long LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            long CountOfRights
        );

        [DllImport("advapi32")]
        public static extern void FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
        private static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr psid,
            ref int cbsid,
            StringBuilder domainName,
            ref int cbdomainLength,
            ref int use
        );

        [DllImport("advapi32.dll")]
        private static extern long LsaClose(IntPtr ObjectHandle);

        [DllImport("kernel32.dll")]
        private static extern int GetLastError();

        [DllImport("advapi32.dll")]
        private static extern long LsaNtStatusToWinError(long status);

        // LSA structures

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // LSA object access policies

        private enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        public static long AddRight(String accountName, String privilegeName)
        {
            long winErrorCode = 0; //contains the last error

            //pointer an size for the SID
            IntPtr sid = IntPtr.Zero;
            int sidSize = 0;
            //StringBuilder and size for the domain name
            StringBuilder domainName = new StringBuilder();
            int nameSize = 0;
            //account-type variable for lookup
            int accountType = 0;

            //get required buffer size
            LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            //allocate buffers
            domainName = new StringBuilder(nameSize);
            sid = Marshal.AllocHGlobal(sidSize);

            //lookup the SID for the account
            Console.Write("LookupAccountName...");
            bool result = LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            if (!result)
            {
                winErrorCode = GetLastError();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed!");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("OK");
                Console.ResetColor();

                //initialize an empty unicode-string
                LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
                //combine all policies
                int access = (int)(
                    LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
                    LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
                    LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
                    LSA_AccessPolicy.POLICY_CREATE_SECRET |
                    LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
                    LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
                    LSA_AccessPolicy.POLICY_NOTIFICATION |
                    LSA_AccessPolicy.POLICY_SERVER_ADMIN |
                    LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
                    LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
                    LSA_AccessPolicy.POLICY_TRUST_ADMIN |
                    LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
                    LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
                    );
                //initialize a pointer for the policy handle
                IntPtr policyHandle = IntPtr.Zero;

                //these attributes are not used, but LsaOpenPolicy wants them to exists
                LSA_OBJECT_ATTRIBUTES ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
                ObjectAttributes.Length = 0;
                ObjectAttributes.RootDirectory = IntPtr.Zero;
                ObjectAttributes.Attributes = 0;
                ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
                ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

                //get a policy handle
                Console.Write("OpenPolicy...");
                uint resultPolicy = LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);
                winErrorCode = LsaNtStatusToWinError(resultPolicy);

                if (winErrorCode != 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed!");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("OK");
                    Console.ResetColor();

                    //Now that we have the SID an the policy,
                    //we can add rights to the account.

                    //initialize an unicode-string for the privilege name
                    LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                    userRights[0] = new LSA_UNICODE_STRING();
                    userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
                    userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
                    userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);

                    //add the right to the account
                    Console.Write("LsaAddAccountRights...");
                    long res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
                    if (res != 0)
                        winErrorCode = LsaNtStatusToWinError(res);
                    else
                        winErrorCode = 0;
                    if (winErrorCode != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed!");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("OK");
                        Console.ResetColor();
                    }

                    LsaClose(policyHandle);
                }
                FreeSid(sid);
            }

            return winErrorCode;
        }

    }

}