using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using static System.Collections.Specialized.BitVector32;
using System.IO;
using System.ServiceProcess;

namespace Tscan
{
    public class ScannerRemoteExec
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            string lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true,
            CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hHandle);
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

        public String RemoteExecScript;
        public String PathToService;
        public String ServiceTextToCompile = @"
using System;
using System.Text; //May 2024
using System.Diagnostics;
using System.ServiceProcess;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace WindowsService
{
    class WindowsService : ServiceBase
    {
        /// <summary>
        /// Public Constructor for WindowsService.
        /// - Put all of your Initialization code here.
        /// </summary>
        public WindowsService()
        {
            this.ServiceName = ""My Windows Service"";
            this.EventLog.Log = ""Application"";

            // These Flags set whether or not to handle that specific
            //  type of event. Set to true if you need it, false otherwise.
            this.CanHandlePowerEvent = true;
            this.CanHandleSessionChangeEvent = true;
            this.CanPauseAndContinue = true;
            this.CanShutdown = true;
            this.CanStop = true;
        }

        /// <summary>
        /// The Main Thread: This is where your Service is Run.
        /// </summary>
        static void Main()
        {
            ServiceBase.Run(new WindowsService());
        }

        /// <summary>
        /// Dispose of objects that need it here.
        /// </summary>
        /// <param name=""disposing"">Whether
        ///    or not disposing is going on.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        /// <summary>
        /// OnStart(): Put startup code here
        ///  - Start threads, get inital data, etc.
        /// </summary>
        /// <param name=""args""></param>
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            //String GoTo = ""OnStart"";
            try
            {
                long ACLGrantResult = grantprivilege.LsaUtility.AddRight(Environment.UserName, ""SeIncreaseQuotaPrivilege""); //May 2024
                System.Security.Principal.WindowsPrincipal foo = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(Environment.CurrentDirectory, ""IsElevated.txt""),
                    ""Admin? "" + foo.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));
                //GotTo = ""Begin Try"";
                String RemoteExecScript = ""RemoteExecScriptString"";
                String[] SplitRemoteExecScript = RemoteExecScript.Split("" "".ToCharArray(), 2);
                System.Security.SecureString SecPass = new System.Security.SecureString();
                foreach (char PassChar in ""PasswordString"") SecPass.AppendChar(PassChar);
                System.Diagnostics.ProcessStartInfo RemoteExecStartInfo =
                    new System.Diagnostics.ProcessStartInfo(SplitRemoteExecScript[0], SplitRemoteExecScript[1]);
                RemoteExecStartInfo.Verb = ""runas"";
                RemoteExecStartInfo.UseShellExecute = false;
                RemoteExecStartInfo.UserName = ""UserNameString"";
                RemoteExecStartInfo.Password = SecPass;
                RemoteExecStartInfo.Domain = ""DomainNameString"";
                RemoteExecStartInfo.LoadUserProfile = true;
                RemoteExecStartInfo.WorkingDirectory = Environment.CurrentDirectory;
                RemoteExecStartInfo.CreateNoWindow = true;
                RemoteExecStartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                RemoteExecStartInfo.RedirectStandardOutput = true;
                RemoteExecStartInfo.RedirectStandardError = true;
                System.Diagnostics.Process RemoteExecProcess = new System.Diagnostics.Process();
                RemoteExecProcess = System.Diagnostics.Process.Start(RemoteExecStartInfo);
                System.IO.StreamReader ReaderOutput = RemoteExecProcess.StandardOutput;
                System.IO.StreamReader ReaderError = RemoteExecProcess.StandardError;
                String StandardOutput = """";
                //GotTo = ""Before While"";
                try
                {
                    while (!RemoteExecProcess.HasExited)
                    {
                        StandardOutput += ReaderOutput.ReadToEnd();
                        StandardOutput += ReaderError.ReadToEnd();
                        RemoteExecProcess.WaitForExit(TimeSpan.FromSeconds(1).Milliseconds);
                    }                                                                                                                                           
                }
                catch(System.ComponentModel.Win32Exception) {}
                //GotTo = ""Before Write Errors"";
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(System.IO.Directory.GetParent(Environment.CurrentDirectory).ToString(), 
                    ""RemoteExecOutput.txt""), StandardOutput);
                if(RemoteExecProcess.ExitCode != 0)
                    System.IO.File.WriteAllText(
                        System.IO.Path.Combine(System.IO.Directory.GetParent(Environment.CurrentDirectory).ToString(), 
                        ""RemoteExecExitCode.txt""), RemoteExecProcess.ExitCode.ToString());
            }
            catch (Exception e)
            {
                System.Diagnostics.StackTrace Stack = new System.Diagnostics.StackTrace(e);
                System.Diagnostics.StackFrame Frame = Stack.GetFrame(Stack.FrameCount - 1);
                Int32 Line = Frame.GetFileLineNumber();
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(System.IO.Directory.GetParent(Environment.CurrentDirectory).ToString(), 
                    ""RemoteExecExitCode.txt""), e.Message + "" "" + e.GetType().FullName +"" "" + Line);
            }
            System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
        }
    /// <summary>
    /// OnStop(): Put your stop code here
    /// - Stop threads, set final data, etc.
    /// </summary>
    protected override void OnStop()
        {
            base.OnStop();
        }

        /// <summary>
        /// OnPause: Put your pause code here
        /// - Pause working threads, etc.
        /// </summary>
        protected override void OnPause()
        {
            base.OnPause();
        }

        /// <summary>
        /// OnContinue(): Put your continue code here
        /// - Un-pause working threads, etc.
        /// </summary>
        protected override void OnContinue()
        {
            base.OnContinue();
        }

        /// <summary>
        /// OnShutdown(): Called when the System is shutting down
        /// - Put code here when you need special handling
        ///   of code that deals with a system shutdown, such
        ///   as saving special data before shutdown.
        /// </summary>
        protected override void OnShutdown()
        {
            base.OnShutdown();
        }

        /// <summary>
        /// OnCustomCommand(): If you need to send a command to your
        ///   service without the need for Remoting or Sockets, use
        ///   this method to do custom methods.
        /// </summary>
        /// <param name=""command"">Arbitrary Integer between 128 & 256</param>
        protected override void OnCustomCommand(int command)
        {
            //  A custom command can be sent to a service by using this method:
            //#  int command = 128; //Some Arbitrary number between 128 & 256
            //#  ServiceController sc = new ServiceController(""NameOfService"");
            //#  sc.ExecuteCommand(command);

            base.OnCustomCommand(command);
        }

        /// <summary>
        /// OnPowerEvent(): Useful for detecting power status changes,
        ///   such as going into Suspend mode or Low Battery for laptops.
        /// </summary>
        /// <param name=""powerStatus"">The Power Broadcast Status
        /// (BatteryLow, Suspend, etc.)</param>
        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            return base.OnPowerEvent(powerStatus);
        }

        /// <summary>
        /// OnSessionChange(): To handle a change event
        ///   from a Terminal Server session.
        ///   Useful if you need to determine
        ///   when a user logs in remotely or logs off,
        ///   or when someone logs into the console.
        /// </summary>
        /// <param name=""changeDescription"">The Session Change
        /// Event that occured.</param>
        protected override void OnSessionChange(
                  SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
        }
    }
}
//https://github.com/DmytroGerasymchuk/grantprivilege/blob/master/src/raw/LsaUtility.cs

namespace grantprivilege
{

    public class LsaUtility
    {

        // LSA functions

        [DllImport(""advapi32.dll"", PreserveSig = true)]
        private static extern UInt32 LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            Int32 DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport(""advapi32.dll"", SetLastError = true, PreserveSig = true)]
        private static extern long LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            long CountOfRights
        );

        [DllImport(""advapi32"")]
        public static extern void FreeSid(IntPtr pSid);

        [DllImport(""advapi32.dll"", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
        private static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            IntPtr psid,
            ref int cbsid,
            StringBuilder domainName,
            ref int cbdomainLength,
            ref int use
        );

        [DllImport(""advapi32.dll"")]
        private static extern long LsaClose(IntPtr ObjectHandle);

        [DllImport(""kernel32.dll"")]
        private static extern int GetLastError();

        [DllImport(""advapi32.dll"")]
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
            Console.Write(""LookupAccountName..."");
            bool result = LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            if (!result)
            {
                winErrorCode = GetLastError();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(""Failed!"");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(""OK"");
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
                Console.Write(""OpenPolicy..."");
                uint resultPolicy = LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);
                winErrorCode = LsaNtStatusToWinError(resultPolicy);

                if (winErrorCode != 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(""Failed!"");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(""OK"");
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
                    Console.Write(""LsaAddAccountRights..."");
                    long res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
                    if (res != 0)
                        winErrorCode = LsaNtStatusToWinError(res);
                    else
                        winErrorCode = 0;
                    if (winErrorCode != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(""Failed!"");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(""OK"");
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
";
        /// <summary>
        /// This allows you to run a program on a the local system
        /// </summary>
        /// 
        //private void Elevate()
        //{
        //    //https://github.com/poweradminllc/PAExec/blob/master/Process.cpp
        //    String Privileges = "SeCreateTokenPrivilege,SeAssignPrimaryTokenPrivilege,SeLockMemoryPrivilege,SeIncreaseQuotaPrivilege,SeMachineAccountPrivilege," +
        //            "SeTcbPrivilege,SeSecurityPrivilege,SeTakeOwnershipPrivilege,SeLoadDriverPrivilege,SeSystemProfilePrivilege,SeSystemtimePrivilege,SeProfileSingleProcessPrivilege," +
        //            "SeIncreaseBasePriorityPrivilege,SeCreatePagefilePrivilege,SeCreatePermanentPrivilege,SeBackupPrivilege,SeRestorePrivilege,SeShutdownPrivilege,SeDebugPrivilege," +
        //            "SeAuditPrivilege,SeSystemEnvironmentPrivilege,SeChangeNotifyPrivilege,SeRemoteShutdownPrivilege,SeUndockPrivilege,SeSyncAgentPrivilege,SeEnableDelegationPrivilege," +
        //            "SeManageVolumePrivilege,SeImpersonatePrivilege,SeCreateGlobalPrivilege,SeTrustedCredManAccessPrivilege,SeRelabelPrivilege,SeIncreaseWorkingSetPrivilege," +
        //            "SeTimeZonePrivilege,SeCreateSymbolicLinkPrivilege";
        //    foreach (String Privilege in Privileges.Split(",".ToCharArray()))
        //    {
        //        var hProcessToken = IntPtr.Zero;
        //        // Enable SeIncreaseQuotaPrivilege in this process.  (This won't work if current process is not elevated.)
        //        try
        //        {
        //            var process = GetCurrentProcess();
        //            if (!OpenProcessToken(process, 0x0020, ref hProcessToken))
        //                return;

        //            var tkp = new TOKEN_PRIVILEGES
        //            {
        //                PrivilegeCount = 1,
        //                Privileges = new LUID_AND_ATTRIBUTES[1]
        //            };

        //            if (!LookupPrivilegeValue(null, Privilege, ref tkp.Privileges[0].Luid))
        //                return;

        //            tkp.Privileges[0].Attributes = 0x00000002;

        //            if (!AdjustTokenPrivileges(hProcessToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero))
        //                return;
        //        }
        //        finally
        //        {
        //            CloseHandle(hProcessToken);
        //        }

        //    }

        //}
        /// <summary>
        /// This allows you to run a program on a the local system
        /// </summary>
        /// 
        private void IsElevated(String Server)
        {
            System.Security.Principal.WindowsPrincipal foo = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
            System.IO.File.WriteAllText(
                System.IO.Path.Combine(Environment.CurrentDirectory, Server + "_IsElevated.txt"),
                "Admin? " + foo.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));

        }
        /// <summary>
        /// This allows you to run a program on a the local system
        /// </summary>
        /// 
        private void LocalExec(String Server, String User, String Pass)
        {
            LocalExec(Server, User, Pass, RemoteExecScript);
        }
        /// <summary>
        /// This allows you to run a program on a the local system
        /// </summary>
        /// 
        private void LocalExec(String Server, String User, String Pass, String Command)
        {
            //getuserhandle other code paths so unecessary
            //    EnablePrivilege(SE_DEBUG_NAME)
            //    EnablePrivilege(SE_RESTORE_NAME);
            //    EnablePrivilege(SE_BACKUP_NAME);
            //    
            //Not use system account or current user
            //    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            //    EnablePrivilege(SE_INCREASE_QUOTA_NAME);
            //    EnablePrivilege(SE_IMPERSONATE_NAME);
            //    ImpersonateLoggedOnUser(hUser);
            // .net 4.0 system.security se impersonation
            try
            {
                //Elevate();
                long ACLGrantResult = grantprivilege.LsaUtility.AddRight(Environment.UserName, "SeIncreaseQuotaPrivilege");
                IsElevated(Server);
                String[] SplitRemoteExecScript =
                    Command.Replace("\\\"", "\"").Replace("\\\\", "\\").Split(" ".ToCharArray(), 2);
                System.Security.SecureString SecPass = new System.Security.SecureString();
                foreach (char PassChar in Tscan.Scan.Password) SecPass.AppendChar(PassChar);
                System.Diagnostics.ProcessStartInfo LocalExecStartInfo =
                    new System.Diagnostics.ProcessStartInfo(SplitRemoteExecScript[0], SplitRemoteExecScript[1]);
                LocalExecStartInfo.Verb = "runas";
                LocalExecStartInfo.UseShellExecute = true;
                //LocalExecStartInfo.UserName = Environment.UserName;
                //LocalExecStartInfo.Password = SecPass;
                //LocalExecStartInfo.Domain = Environment.UserDomainName;
                LocalExecStartInfo.LoadUserProfile = true;
                LocalExecStartInfo.WorkingDirectory = Environment.CurrentDirectory;
                LocalExecStartInfo.CreateNoWindow = true;
                LocalExecStartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                //LocalExecStartInfo.RedirectStandardOutput = true;
                //LocalExecStartInfo.RedirectStandardError = true;
                System.Diagnostics.Process LocalExecProcess = new System.Diagnostics.Process();
                LocalExecProcess = System.Diagnostics.Process.Start(LocalExecStartInfo);
                //System.IO.StreamReader ReaderOutput = LocalExecProcess.StandardOutput;
                //System.IO.StreamReader ReaderError = LocalExecProcess.StandardError;
                String StandardOutput = "";
                try
                {
                    while (!LocalExecProcess.HasExited)
                    {
                        //StandardOutput += ReaderOutput.ReadToEnd();
                        //StandardOutput += ReaderError.ReadToEnd();
                        LocalExecProcess.WaitForExit(TimeSpan.FromSeconds(1).Milliseconds);
                    }
                }
                catch (System.ComponentModel.Win32Exception) { }
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(Environment.CurrentDirectory, Server + "_LocalExecOutput.txt"),
                    StandardOutput);
                if (LocalExecProcess.ExitCode != 0)
                    System.IO.File.WriteAllText(
                        System.IO.Path.Combine(Environment.CurrentDirectory, Server + "_LocalExecExitCode.txt"),
                        LocalExecProcess.ExitCode.ToString());
            }
            catch (Exception e)
            {
                //Error messages are low priority
                try
                {
                    System.Diagnostics.StackTrace Stack = new System.Diagnostics.StackTrace(e);
                    System.Diagnostics.StackFrame Frame = Stack.GetFrame(Stack.FrameCount - 1);
                    Int32 Line = Frame.GetFileLineNumber();
                    System.IO.File.WriteAllText(
                        System.IO.Path.Combine(Environment.CurrentDirectory, Server + "_LocalExecExitCode.txt"),
                        e.Message + " " + e.GetType().FullName + " " + Line);
                }
                catch (System.IO.IOException)
                { } // Error swallower.  Commonly sees readtoend
            }
            //Most of these settings have little bearing on access denied error messages
        }
        /// <summary>
        /// This allows you to run a program using PsExec if available in the local directory
        /// </summary>
        /// 
        public bool PsExec(String Server, String Domain, String User, String Pass)
        {
            String Command = RemoteExecScript;
            String[] SplitRemoteExecScript =
                Command.Replace("\\\"", "\"").Replace("\\\\", "\\").Split(" ".ToCharArray(), 2);
            Command = "PsExec.exe \\\\" + Server + " -u " + Domain + "\\" + User + " -p \"" + Pass + "\" -h -c -d -accepteula -nobanner \""
                    + SplitRemoteExecScript[0] + "\" \"" + SplitRemoteExecScript[1] + "\"";
            LocalExec(Server, User, Pass, Command);
            return true;
        }
        /// <summary>
        /// This allows you to run a program using PsExec if available in the local directory
        /// </summary>
        /// 
        public bool PsExecTscan(String Server, String Domain, String User, String Pass)
        {
            String Command = "Tscan.exe //Type:ThisMachine";
            String[] SplitRemoteExecScript =
                Command.Replace("\\\"", "\"").Replace("\\\\", "\\").Split(" ".ToCharArray(), 2);
            Command = "PsExec.exe \\\\" + Server + " -u " + Domain + "\\" + User + " -p \"" + Pass + "\" -h -c -d -accepteula -nobanner \""
                    + SplitRemoteExecScript[0] + "\" \"" + SplitRemoteExecScript[1] + "\"";
            LocalExec(Server, User, Pass, Command);
            return true;
        }
        /// <summary>
        /// This compiles a service for remote execution
        /// </summary>
        ///  
        public void CompileService()
        {
            if (Environment.MachineName.Equals(Environment.UserDomainName, StringComparison.CurrentCultureIgnoreCase))
            {
                //CompileService("Environment.MachineName", Environment.UserName, Tscan.Scan.Password);
                CompileService("Environment.MachineName", "\"" + Environment.UserName + "\"", Tscan.Scan.Password);
            }
            else
            {
                CompileService("\"" + Environment.UserDomainName + "\"", "\"" + Environment.UserName + "\"", Tscan.Scan.Password);
            }
        }
        /// <summary>
        /// This compiles a service for remote execution
        /// </summary>
        ///  
        public void CompileService(String Domain, String User, String Pass)
        {
            ServiceTextToCompile = ServiceTextToCompile.Replace("RemoteExecScriptString", RemoteExecScript);
            ServiceTextToCompile = ServiceTextToCompile.Replace("PasswordString", Pass);
            ServiceTextToCompile = ServiceTextToCompile.Replace("\"UserNameString\"", User);
            ServiceTextToCompile = ServiceTextToCompile.Replace("\"DomainNameString\"", Domain);
            try
            {
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(Environment.CurrentDirectory, "Service.cs"), ServiceTextToCompile);
            }
            catch { }

            Microsoft.CSharp.CSharpCodeProvider provider =
                new Microsoft.CSharp.CSharpCodeProvider();
            System.CodeDom.Compiler.CompilerParameters parameters =
                new System.CodeDom.Compiler.CompilerParameters();
            //parameters.CompilerOptions = "/unsafe";
            parameters.ReferencedAssemblies.Add("System.dll");
            //parameters.ReferencedAssemblies.Add("System.Diagnostics.dll");//Doesn't exist
            parameters.ReferencedAssemblies.Add("System.ServiceProcess.dll");
            parameters.ReferencedAssemblies.Add("System.Windows.Forms.dll");
            parameters.GenerateInMemory = false;
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = "TempService.exe";
            System.CodeDom.Compiler.CompilerResults results =
                provider.CompileAssemblyFromSource(parameters, ServiceTextToCompile);
            if (results.Errors.HasErrors)
            {
                System.Windows.Forms.MessageBox.Show(results.Errors[0].ErrorText);
                return;
            }
            PathToService = results.PathToAssembly;
            //System.Reflection.Assembly Assembly = results.CompiledAssembly;
            //Type program = Assembly.GetType("First.Program");
            //System.Reflection.MethodInfo main = program.GetMethod("Main");
            //main.Invoke(null, null);
        }
        /// <summary>
        /// This creates a service using remote service. This is legacy code.
        /// </summary>
        /// 
        public void CreateServiceUsingRemoteService(String Server, String LocalDirectory, String User, String Pass, String Domain, String Suffix)
        {
            if (Server.Equals(Domain, StringComparison.CurrentCultureIgnoreCase)) Domain = ".";
            IntPtr Handle;
            if (Server.Equals(Environment.MachineName, StringComparison.CurrentCultureIgnoreCase))
            {
                Handle = OpenSCManager(null, null, 0xF003Fu);
                //sc_manager_all_access = 0xF003Fu truecrypt uses this hex
            }
            else
            {
                Handle = OpenSCManager(Server, null, 0xF003Fu);
            }
            if (Handle.Equals(IntPtr.Zero))
            {
                System.Windows.Forms.MessageBox.Show(Marshal.GetLastWin32Error().ToString());
                //I get a lot of 5 access denied fixed by app.manifest requireAdministrator
            }
            else
            {
                IntPtr serviceHandle = CreateService(Handle, "Temp" + Suffix, "Temp Service", 0xF01FFu, 0x10u,
                    0x3u, 0x1u, LocalDirectory + "\\TempService.exe", null, null, null, User + "@" + Domain, Pass); //Domain + "\\" + User, Pass);
                //Service_All_Access = 0xF01FFu truecrypt uses this hex
                if (serviceHandle.Equals(IntPtr.Zero))
                {
                    System.Windows.Forms.MessageBox.Show("CreateService " + Marshal.GetLastWin32Error().ToString());
                    //I get bad pointer due to failed openscmanager Error_Invalid_Handle 6
                    //I get Error_Invalid_Parameter 87 on lpdwTagId with "0" using null works
                    //1057 0x421 ERROR_INVALID_SERVICE_ACCOUNT
                    //https://stackoverflow.com/questions/8811590/calling-createservice-when-explicitly-specifying-the-local-domain-in-lpservicest
                    //1072 on failed service delete try restarting remote machine
                }
                else
                {
                    CloseServiceHandle(serviceHandle);
                }
                CloseServiceHandle(Handle);
            }
        }
        /// <summary>
        /// This allows you to run a program on a remote system usually as a subset of a server pool
        /// </summary>
        /// 
        public bool RemoteExec(String Server, String Domain, String User, String Pass)
        {
            //powershell -executionpolicy bypass -command \"& {$env:username >> test.txt}\"
            //C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -executionpolicy bypass -command \"& {}\"
            //powershell remote script issues chaining to uac available as runas
            //cpuz_x32.exe -txt=cpuz.txt
            //requires uac elevation which is available as runas
            //local service limitations on write
            if (Server.Equals(Domain, StringComparison.CurrentCultureIgnoreCase)) return false;
            String RemoteDirectory = "c:\\windows";
            String LocalDirectory = RemoteDirectory + "\\TempService";
            if (Server.Equals(Environment.MachineName, StringComparison.CurrentCultureIgnoreCase))
            {
                //RemoteDirectory = RemoteDirectory + "\\TempService";
                //admin$ doesn't exist for local machine without a network
                LocalExec(Server, User, Pass);
                return true;
            }
            else if (RemoteDirectory.Contains("c:\\windows"))
            {
                RemoteDirectory = "\\\\" + Server + "\\" + RemoteDirectory.Replace("c:\\windows", "admin$") +
                    "\\TempService";
            }
            else
            {
                RemoteDirectory = "\\\\" + Server + "\\" + RemoteDirectory.Replace(":", "$") + "\\TempService";
            }
            System.Management.ManagementScope Scope = Tscan.Scan.SetupScope(Server, Domain, User, Pass);
            try
            {
                Scope.Connect();
            }
            catch
            {
                return false;
            }
            String Suffix = ""; new System.Random().Next(1, 999).ToString();
            //New instances
            System.Management.ManagementPath Path =
                new System.Management.ManagementPath("Win32_Service.Name='" + Suffix + "'");
            //System.Management.ManagementObject Obj;
            System.Management.ManagementBaseObject OutParams;
            uint ReturnValue = 0;

            //Stop service old
            SingleWMIMethod(Scope, "StopService", Suffix);
            System.Threading.Thread.Sleep(TimeSpan.FromSeconds(15));

            //Delete service old
            SingleWMIMethod(Scope, "Delete", Suffix);
            System.Threading.Thread.Sleep(TimeSpan.FromSeconds(15));

            System.Net.NetworkCredential Cred = new System.Net.NetworkCredential(Domain + "\\" + User, Pass);
            System.Net.CredentialCache Cache = new System.Net.CredentialCache();
            Cache.Add(new System.Uri("\\\\" + Server + "\\admin$\\"), "basic", Cred);
            //basic, digest, ntlm, kerberos

            //error on nonexistance
            if (System.IO.Directory.Exists(RemoteDirectory))
                System.IO.Directory.Delete(RemoteDirectory, true);
            System.Threading.Thread.Sleep(TimeSpan.FromSeconds(15));

            try
            {
                System.IO.Directory.CreateDirectory(RemoteDirectory);
            }
            catch (System.IO.IOException)
            {
                //MessageBox.Show(e.Message);
                return false;
            }
            if (!RemoteExecScript.ToLower().Contains("Powershell".ToLower()))
            {
                System.IO.File.Copy(Environment.CurrentDirectory + "\\" + RemoteExecScript.Split(" ".ToCharArray())[0],
                    RemoteDirectory + "\\" + RemoteExecScript.Split(" ".ToCharArray())[0], true);
            }
            Boolean Caught = true;
            for (Int16 i = 0; i < 3 && Caught; i++)
            {
                if (i > 0) System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                Caught = false;
                try
                {
                    //copy fails 1/2 the time in .net 3.5 with IOException
                    System.IO.File.Copy(PathToService, RemoteDirectory + "\\TempService.exe", true);
                }
                catch (System.IO.IOException)
                {
                    //MessageBox.Show(e.Message);
                    Caught = true;
                }
            }
            //try
            //{
            //    System.IO.File.Copy(PathToService, RemoteDirectory + "\\TempService.exe", true);
            //}
            //catch { }
            //create service new
            System.Management.ManagementClass ServiceManagementClass =
                new System.Management.ManagementClass(Scope, new System.Management.ManagementPath("Win32_Service"), new System.Management.ObjectGetOptions());
            System.Management.ManagementBaseObject InParams = ServiceManagementClass.GetMethodParameters("Create");
            InParams["Name"] = "Temp" + Suffix;
            InParams["DisplayName"] = "Temp Service";
            InParams["ServiceType"] = 16;  //16, own process
            InParams["ErrorControl"] = 0;  //0, hide errors, 1, show errors
            InParams["StartMode"] = "Automatic";
            InParams["DesktopInteract"] = false; //previous incorrect false
            InParams["PathName"] = LocalDirectory + "\\TempService.exe";

            //CreateServiceUsingRemoteService(Server, LocalDirectory,User, Pass, Domain, "");

            //http://www.pinvoke.net/default.aspx/advapi32.CreateService
            //System.ServiceProcess.ServiceController[] Services = 
            //  System.ServiceProcess.ServiceController.GetServices(Server);

            //hService = ::CreateService(
            //            hSCM, remoteServiceName, remoteServiceName,
            //            SERVICE_ALL_ACCESS, //0xF01FF, access right winsvc.h, DesiredAccess, c++ option
            //            serviceType,
            //            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            //            svcExePath,
            //            NULL, NULL, 
            //            NULL, NULL ); //using LocalSystem
            // https://stackoverflow.com/questions/25619112/how-do-i-fix-the-error1069-the-service-did-not-start-due-to-logon-failure
            //InParams["StartName"] = User + "@" + Domain;
            InParams["StartName"] = Domain.ToLower() + "\\" + User.ToLower();
            InParams["StartPassword"] = Pass;
            //InParams["LoadOrderGroup"]
            //InParams["LoadOrderGroupDependencies[]"]
            //InParams["ServiceDependencies[]"]
            System.Management.InvokeMethodOptions methodOptions =
                new System.Management.InvokeMethodOptions(null, System.TimeSpan.FromMinutes(5));
            OutParams = ServiceManagementClass.InvokeMethod("Create", InParams, methodOptions);
            ReturnValue = System.Convert.ToUInt32(OutParams.Properties["ReturnValue"].Value);
            if (ReturnValue != 0) MessageBox.Show("Win32_Service.Create " + ReturnValue);
            // 8 means interactive process InParams["DesktopInteract"] = true; Administrator@Computer but not really

            //CreateServiceUsingRemoteService(Server, LocalDirectory, User, Pass, Domain, Suffix);

            if (true)
            {
                Path = new System.Management.ManagementPath("Win32_Service.Name='Temp" + Suffix + "'");
                System.Management.ManagementObject Obj = new System.Management.ManagementObject(Scope, Path, new System.Management.ObjectGetOptions());
                InParams = Obj.GetMethodParameters("Change");
                //InParams["StartName"] = User + "@" + Domain;
                InParams["StartName"] = Domain.ToLower() + "\\" + User.ToLower();
                InParams["StartPassword"] = Pass;
                methodOptions = new System.Management.InvokeMethodOptions(null, System.TimeSpan.FromMinutes(5));
                OutParams = Obj.InvokeMethod("Change", InParams, methodOptions);
                ReturnValue = System.Convert.ToUInt32(OutParams.Properties["ReturnValue"].Value);
                if (ReturnValue != 0) MessageBox.Show("Win32_Service.Change " + ReturnValue);
                //code 8 on user@domain
            }

            //Start service
            SingleWMIMethod(Scope, "StartService", Suffix);

            //Return code 13 The service failed to find the service needed from a dependent service
            //startname = Administrator
            //Return code 15 failed authentication when using startname = local admins
            //Access is denied
            //at System.Diagnostics.Process.StartWithCreateProcess(ProcessStartInfo startInfo)
            //at System.Diagnostics.Process.Start(ProcessStartInfo startInfo)
            //at WindowsService.WindowsService.OnStart(String[] args)

            System.Threading.Thread.Sleep(TimeSpan.FromMinutes(10));
            //this should be enough for most patches and installers on /qb
            //add 1 minutes for stop and delete twice
            //the program may run after the service has stopped
            SingleWMIMethod(Scope, "StopService", Suffix);
            System.Threading.Thread.Sleep(TimeSpan.FromSeconds(15));

            SingleWMIMethod(Scope, "Delete", Suffix);
            System.Threading.Thread.Sleep(TimeSpan.FromSeconds(15));

            System.IO.Directory.CreateDirectory(Environment.CurrentDirectory + "\\" + Server);

            foreach (String SourceFile in System.IO.Directory.GetFiles(RemoteDirectory))
            {
                System.IO.File.Copy(SourceFile,
                    Environment.CurrentDirectory + "\\" + Server + "\\" +
                    System.IO.Path.GetFileName(SourceFile), true);
            }
            if (System.IO.File.Exists(System.IO.Path.Combine(
                System.IO.Directory.GetParent(RemoteDirectory).ToString(), "RemoteExecExitCode.txt")))
                System.IO.File.Copy(System.IO.Path.Combine(
                System.IO.Directory.GetParent(RemoteDirectory).ToString(), "RemoteExecExitCode.txt"),
                Environment.CurrentDirectory + "\\" + Server + "\\" + "RemoteExecExitCode.txt", true);
            if (System.IO.File.Exists(System.IO.Path.Combine(
                System.IO.Directory.GetParent(RemoteDirectory).ToString(), "RemoteExecOutput.txt")))
                System.IO.File.Copy(System.IO.Path.Combine(
                System.IO.Directory.GetParent(RemoteDirectory).ToString(), "RemoteExecOutput.txt"),
                Environment.CurrentDirectory + "\\" + Server + "\\" + "RemoteExecOutput.txt", true);
            System.IO.Directory.Delete(RemoteDirectory, true);

            //MessageBox.Show("RemoteExec Server Done: " + Server);
            return true;
        }
        /// <summary>
        /// Run one wmi method
        /// </summary>
        ///  
        public UInt32 SingleWMIMethod(System.Management.ManagementScope Scope, String Method, String Suffix)
        {
            UInt32 ReturnValue = 0;
            try
            {
                System.Management.ManagementPath Path =
                    new System.Management.ManagementPath("Win32_Service.Name='Temp" + Suffix + "'");
                System.Management.ManagementObject Obj =
                    new System.Management.ManagementObject(Scope, Path, new System.Management.ObjectGetOptions());
                System.Management.ManagementBaseObject OutParams =
                    Obj.InvokeMethod(Method, (System.Management.ManagementBaseObject)null, null);
                ReturnValue = System.Convert.ToUInt32(OutParams.Properties["ReturnValue"].Value);
                if (ReturnValue != 0) MessageBox.Show("Win32_Service." + Method + " " + ReturnValue);
            }
            catch { }
            return ReturnValue;
        }
    }
}
