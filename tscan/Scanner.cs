using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Drawing;
using System.ComponentModel.Design;
using System.Text.RegularExpressions;
using System.Threading;

namespace Tscan
{
    public class Scanner
    {
        [DllImport("IPHLPAPI.DLL", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int RegConnectRegistry(string lpmachineName, int hKey, ref IntPtr phKResult);
        [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
        extern private static int RegEnumKeyEx(IntPtr hkey,
            uint index,
            StringBuilder lpName,
            ref uint lpcbName,
            IntPtr reserved,
            IntPtr lpClass,
            IntPtr lpcbClass,
            out long lpftLastWriteTime);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
          IntPtr hKey,
          string subKey,
          int ulOptions,
          int samDesired,
          out IntPtr hkResult);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref RegistryValueKind lpType,
            IntPtr lpData,
            ref int lpcbData);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref RegistryValueKind lpType,
            StringBuilder lpData,
            ref int lpcbData);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref RegistryValueKind lpType,
            Byte[] lpData,
            ref int lpcbData);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint RegEnumValue(
          IntPtr hKey,
          uint dwIndex,
          StringBuilder lpValueName,
          ref uint lpcValueName,
          IntPtr lpReserved,
          IntPtr lpType,
          IntPtr lpData,
          IntPtr lpcbData);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(
            IntPtr hKey);

        public int IntScanType;
        public Boolean ADOnly;
        public Boolean ScanInternet;
        public Boolean DoPass;
        Int32 IntDone;
        Int32 IntSQL;
        Int32 IntPort;
        Int32 IntServer;
        public String Password;
        public String SearchTerm;
        public String SearchObjects;
        public String MACLookupURI;
        public String[] WMIPasswords;
        public String[] WMIUsernames;
        public String[] XMLElements;
        public String ServerListFilename;
        //public System.Collections.Specialized.StringDictionary ServerList;
        public System.Collections.Concurrent.ConcurrentDictionary<String, String> ServerList;
        public ScannerActiveDirectory ScanAD;
        public ScannerRemoteExec RemoteExec;
        public Progress ProgressForm;
        /// <summary>
        /// Constructor for the main object
        /// </summary>
        /// 
        public Scanner()
        {
            IntScanType = 0;
            ADOnly = false;
            IntDone = 0;
            IntSQL = 0;
            IntPort = 0;
            ServerListFilename = "";
            ServerList = new System.Collections.Concurrent.ConcurrentDictionary<String, String>();
            ScanAD = new ScannerActiveDirectory();
            RemoteExec = new ScannerRemoteExec();
            String[] WMIPasswordsTemp = { Password, "password", "123456", "" };
            WMIPasswords = WMIPasswordsTemp;
            //SplashData 4+2% limited to avoid account lockout
            String[] WMIUsernamesTemp = {Environment.UserName, "administrator",
                "Administrator", "user1", "admin", "demo", "db2admin", "Admin", "sql"};
            WMIUsernames = WMIUsernamesTemp;
            //rapid7 several are 1/10k
        }
        /// <summary>
        /// This gets a list of names of values using advapi.dll
        /// </summary>
        /// 
        public List<String> GetValueNames(IntPtr hKey)
        {
            List<String> sc = new List<String>();
            try
            {
                uint i = 0;
                uint ret;
                uint NameSize;
                StringBuilder sb = new StringBuilder(1024);
                //String[] ans = new String[1];

                // quick sanity check
                if (hKey.Equals(IntPtr.Zero))
                {
                    return sc;
                    //throw new ApplicationException("Cannot access a closed registry key");
                }

                while (true)
                {
                    NameSize = 1024;
                    try
                    {
                        ret = RegEnumValue(hKey, i, sb, ref NameSize, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    }
                    catch
                    {
                        return sc;
                    }
                    if (ret != 0) return sc;
                    sc.Add(sb.ToString());
                    i++;
                }
            }
            catch
            {
                return sc;
            }
        }
        /// <summary>
        /// This opens a key using advapi.dll
        /// </summary>
        /// 
        public IntPtr RegOpenKey(IntPtr rootKey, string keyPath)
        {
            IntPtr hKey = IntPtr.Zero;
            if (RegOpenKeyEx(rootKey, keyPath, 0, 131097, out hKey) == 0)
            {
                return hKey;
            }
            return IntPtr.Zero;
        }
        /// <summary>
        /// This gets a value belonging to a name using advapi.dll
        /// </summary>
        /// 
        private String RegQueryValue(IntPtr hKey, string valueName)
        {
            int size = 1024;
            string keyValue = null;
            Byte[] bytes = null;
            IntPtr Tester = IntPtr.Zero;
            StringBuilder keyBuffer = new StringBuilder(1024);
            RegistryValueKind type = RegistryValueKind.String;
            //StringBuilder keyBuffer = new StringBuilder((int)size);
            if (RegQueryValueEx(hKey, valueName, 0, ref type, Tester, ref size) == 0)
            {
                keyValue = ScrubString(type.ToString()) + "\",\"";
                if (type == RegistryValueKind.String || type == RegistryValueKind.ExpandString)
                {
                    keyBuffer = new StringBuilder(size);
                    RegQueryValueEx(hKey, valueName, 0, ref type, keyBuffer, ref size);
                    keyValue += ScrubString(keyBuffer.ToString());
                }
                else if (type == RegistryValueKind.DWord || type == RegistryValueKind.QWord)
                {
                    bytes = new Byte[size];
                    RegQueryValueEx(hKey, valueName, 0, ref type, bytes, ref size);
                    if (bytes != null && size == 4) keyValue += ScrubString(BitConverter.ToUInt32(bytes, 0).ToString());
                    else if (bytes != null && size == 8) keyValue += ScrubString(BitConverter.ToUInt64(bytes, 0).ToString());
                }
            }
            try
            {
                //RegCloseKey(hKey);
            }
            catch { }

            return (keyValue);
        }
        /// <summary>
        /// This lists keys using advapi.dll
        /// </summary>
        /// 
        public List<String> RegEnumKey(IntPtr hKey)
        {
            int ret = 0;
            uint NameSize = 0;
            uint i = 0;
            List<String> Keys = new List<string>();
            StringBuilder sb = new StringBuilder(256);
            long Out;
            while (true)
            {
                NameSize = 255 + 1;
                try
                {
                    ret = RegEnumKeyEx(hKey, i, sb, ref NameSize, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out Out);
                }
                catch
                {
                    return Keys;
                }
                if (ret != 0) return Keys;
                else Keys.Add(sb.ToString());
                i++;
            }
            ;
        }
        /// <summary>
        /// This connects to remote reg using advapi.dll
        /// </summary>
        /// 
        public IntPtr ConnectToRemoteReg(String Server, int HKEY, ref bool bOK)
        {
            int iReturn = 0;
            IntPtr iResult = IntPtr.Zero;
            int HKLM = unchecked((int)0x80000002);
            if (HKEY == null) HKEY = HKLM;

            iReturn = RegConnectRegistry(@"\\" + Server, HKEY, ref iResult);

            if (iReturn == 0)
            {
                bOK = true;
                return iResult;
            }
            else
            {
                bOK = false;
            }

            return IntPtr.Zero;
        }
        /// <summary>
        /// This connects a remote registry key.
        /// </summary>
        /// 
        public IntPtr ConnectToRemoteReg(String Server, RegistryHive Hive, String Key)
        {
            bool Success = false;
            IntPtr hRef = IntPtr.Zero;
            int HKEY = unchecked((int)0x80000002);
            String Table = "";
            if (Hive == RegistryHive.LocalMachine) HKEY = unchecked((int)0x80000002);
            hRef = ConnectToRemoteReg(Server, HKEY, ref Success);
            if (!Success) return IntPtr.Zero;
            hRef = RegOpenKey(hRef, Key);
            return hRef;
        }
        /// <summary>
        /// This dumps a remote registry key.
        /// </summary>
        /// 
        public Boolean RegistryDumpAdvapi(String Server, RegistryHive Hive, String Key, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output, Boolean Recursive)
        {
            IntPtr hRef = IntPtr.Zero;
            hRef = ConnectToRemoteReg(Server, Hive, Key);
            String StringTable = RegistryDumpAdvapi(Server, Hive, hRef, Key, Recursive);
            if (String.IsNullOrEmpty(StringTable)) return false;
            if (Output.ContainsKey("RegistryAdvapi"))
            {
                Output["RegistryAdvapi"] += StringTable;
            }
            else
            {
                Output.TryAdd("RegistryAdvapi", StringTable);
            }

            return true;
        }
        /// <summary>
        /// This dumps registry keys and their subkeys, names, and values recursively.
        /// </summary>
        /// 
        public String RegistryDumpAdvapi(String Server, RegistryHive Hive, IntPtr Key, String KeyString, Boolean Recursive)
        {
            Boolean RemoteExecDone = false;
            String Table = "";
            if (Key == null) return Table;
            if (Recursive)
            {
                foreach (String KeyName in RegEnumKey(Key))
                {
                    Thread.Sleep(1);
                    if (!String.IsNullOrEmpty(KeyName))
                        Table += RegistryDumpAdvapi(Server, Hive, ConnectToRemoteReg(Server, Hive, KeyString + "\\" + KeyName), KeyString + "\\" + KeyName, Recursive);
                }
            }
            foreach (String ValueName in GetValueNames(Key))
            {
                Thread.Sleep(1);
                ValueName.ToString();
                if (true)//Key.GetValueKind(ValueName) == RegistryValueKind.String)
                {
                    try
                    {
                        String Value = RegQueryValue(Key, ValueName);
                        String Row = Server + ",\"" +
                            ScrubString(KeyString) + "\",\"" +
                            ScrubString(ValueName) + "\",\"" +
                            Value + "\"" + Environment.NewLine;
                        if (!RemoteExecDone) FindRegistry(Value, Server);
                        if (!RemoteExecDone) FindRegistry(ValueName, Server);
                        Table += Row;
                    }
                    catch
                    {
                        try
                        {
                            String Value = RegQueryValue(Key, ValueName);
                            String Row = Server + ",\"" +
                                ScrubString(KeyString) + "\",\"" +
                                ScrubString(ValueName) + "\",\"" +
                                Value + "\"" + Environment.NewLine;
                            if (!RemoteExecDone) FindRegistry(Value, Server);
                            if (!RemoteExecDone) FindRegistry(ValueName, Server);
                            Table += Row;
                        }
                        catch { }
                    }
                }
            }
            ;
            return Table;
        }
        /// <summary>
        /// This finds something in a remote registry key for remote exec to be allowed to run, default creds just like registry.
        /// </summary>
        /// 
        public Boolean FindRegistry(String CellValue, String Server)
        {
                foreach (String FindWord in SearchTerm.Split(",".ToCharArray()))
                {
                    if (FindWord.Length > 2
                        && ScrubString(CellValue).ToLower().Contains(FindWord.ToLower()))
                        return RemoteExec.RemoteExec(Server, Environment.UserDomainName, Environment.UserName, Password);
                    else return false;
                }
            return false;
        }
        /// <summary>
        /// This dumps a remote registry key.
        /// </summary>
        /// 
        public Boolean RegistryDump(String Server, RegistryHive Hive, String Key, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output, Boolean Recursive)
        {
            String StringTable = RegistryDump(Server, RegistryKey.OpenRemoteBaseKey(Hive, Server).OpenSubKey(Key), Recursive);
            if (String.IsNullOrEmpty(StringTable)) return false;
            if (Output.ContainsKey("Registry"))
            {
                Output["Registry"] += StringTable;
            }
            else
            {
                Output.TryAdd("Registry", StringTable);
            }

            return true;
        }
        /// <summary>
        /// This dumps registry keys and their subkeys, names, and values recursively.
        /// </summary>
        /// 
        public String RegistryDump(String Server, RegistryKey Key, Boolean Recursive)
        {
            Boolean RemoteExecDone = false;
            String Table = "";
            if (Key == null) return Table;
            if (Recursive)
            {
                foreach (String KeyName in Key.GetSubKeyNames())
                {
                    if (!String.IsNullOrEmpty(KeyName))
                        Table += RegistryDump(Server, Key.OpenSubKey(KeyName), Recursive);
                }
            }
            foreach (String ValueName in Key.GetValueNames())
            {
                ValueName.ToString();
                if (Key.GetValueKind(ValueName) == RegistryValueKind.MultiString)
                {
                    String Values = "";
                    foreach (String Value in (String[])Key.GetValue(ValueName))
                    {
                        Values += ScrubString(Value) + " ";
                    }
                    String Row = Server + ",\"" +
                        ScrubString(Key.Name) + "\",\"" +
                        ScrubString(ValueName) + "\",\"" +
                        Key.GetValueKind(ValueName) + "\",\"" +
                        ScrubString(Values) + "\"" + Environment.NewLine;
                    if (!RemoteExecDone) FindRegistry(Values, Server);
                    if (!RemoteExecDone) FindRegistry(ValueName, Server);
                    Table += Row;
                }
                else if (Key.GetValueKind(ValueName) == RegistryValueKind.String ||
                    Key.GetValueKind(ValueName) == RegistryValueKind.DWord ||
                    Key.GetValueKind(ValueName) == RegistryValueKind.Binary ||
                    Key.GetValueKind(ValueName) == RegistryValueKind.ExpandString ||
                    Key.GetValueKind(ValueName) == RegistryValueKind.QWord)
                {
                    String Value = Key.GetValue(ValueName).ToString();
                    String Row = Server + ",\"" +
                        ScrubString(Key.Name) + "\",\"" +
                        ScrubString(ValueName) + "\",\"" +
                        Key.GetValueKind(ValueName) + "\",\"" + 
                        ScrubString(Value) + "\"" + Environment.NewLine;
                    if (!RemoteExecDone) FindRegistry(Value, Server);
                    if (!RemoteExecDone) FindRegistry(ValueName, Server);
                    Table += Row;
                }
                else
                {
                    String Row = Server + ",\"" +
                        ScrubString(Key.Name) + "\",\"" +
                        ScrubString(ValueName) + "\",\"" +
                        Key.GetValueKind(ValueName) + "\",\"" +
                        "" + "\"" + Environment.NewLine;
                    if (!RemoteExecDone) FindRegistry(ValueName, Server);
                    Table += Row;
                }
            }
            ;
            return Table;
        }
        /// <summary>
        /// This writes a file to disk
        /// </summary>
        /// 
        public void WriteToDisk(String Title, String Table)
        {
            Boolean Caught = true;
            for (Int16 i = 0; i < 3 && Caught; i++)
            {
                if (i > 0) System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                Caught = false;
                try
                {
                    System.IO.File.WriteAllText(System.IO.Path.Combine(
                        Environment.CurrentDirectory, Title), Table);
                }
                catch (System.IO.IOException e)
                {
                    MessageBox.Show(e.Message);
                    Caught = true;
                }
            }
        }
        /// <summary>
        /// The setup for the threadpool and a new thread for the scanner
        /// </summary>
        /// 
        public void ScanNetQueueWorkItem(String ProgressLabel)
        {
            //MACLookup("");
            System.Threading.ThreadPool.QueueUserWorkItem(
                new System.Threading.WaitCallback(ScanNetWorkItem), ProgressLabel);
        }
        /// <summary>
        /// This adjusts the size of the thread pool to fit the processor and memory. Deprecated.
        /// </summary>
        /// 
        public Boolean AreResourcesAvailable()
        {
            int[] MaxThreads = { 0, 0 };
            System.Threading.ThreadPool.GetMaxThreads(out MaxThreads[0], out MaxThreads[1]);
            System.Diagnostics.PerformanceCounter CPUCounter;
            System.Diagnostics.PerformanceCounter RamCounter;
            CPUCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
            RamCounter = new System.Diagnostics.PerformanceCounter("Memory", "Available MBytes");
            float CPUCountAvg = 0;
            for (int i = 0; i < 10; i++)
            {
                CPUCountAvg += CPUCounter.NextValue();
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(1));
                //10 seconds per 144 threads on 1 hour threads is 52k threads per hour
                //This reduces 1 second spikes associated with application launches
            }
            if (CPUCountAvg / 10 > 80 && MaxThreads[0] > Environment.ProcessorCount * 20) //20% free CPU
            {
                MaxThreads[0] -= Environment.ProcessorCount * 10;
                System.Threading.ThreadPool.SetMaxThreads(MaxThreads[0], MaxThreads[1]);
                return false;
            }
            //else if (RamCounter.NextValue() < 200 && MaxThreads[0] > Environment.ProcessorCount * 20) //200MB free
            //{
            //    MaxThreads[0] -= Environment.ProcessorCount * 10;
            //    System.Threading.ThreadPool.SetMaxThreads(MaxThreads[0], MaxThreads[1]);
            //    return false;
            //} //10MB per thread
            else if (MaxThreads[0] < Environment.ProcessorCount * 200) //Maxes out in 10 seconds * 20 steps is 3 min
            {
                MaxThreads[0] += Environment.ProcessorCount * 10;
                System.Threading.ThreadPool.SetMaxThreads(MaxThreads[0], MaxThreads[1]);
                return true;
            }
            else
            {
                return false;
            }
        }
        /// <summary>
        /// This method updates progress
        /// </summary>
        /// 
        public void CountProgress()
        {
            IntPort = 0;
            IntDone = 0;
            IntSQL = 0;
            foreach (String File in System.IO.Directory.GetFiles(Environment.CurrentDirectory))
            {
                if (File.EndsWith("Ping.csv", StringComparison.CurrentCultureIgnoreCase))
                {
                    IntPort++;
                }
                else if (File.EndsWith("Done.txt", StringComparison.CurrentCultureIgnoreCase))
                {
                    IntDone++;
                }
                else if (File.EndsWith("SqlServiceAdvancedProperty.csv", StringComparison.CurrentCultureIgnoreCase))
                {
                    IntSQL++;
                }
            }
        }
        /// <summary>
        /// This method updates progress
        /// </summary>
        /// 
        public void UpdateProgress(String CurrentComputer)
        {
            //CountProgress();
            int[] MaxThreads = { 0, 0 };
            System.Threading.ThreadPool.GetMaxThreads(out MaxThreads[0], out MaxThreads[1]);
            int[] AvailableThreads = { 0, 0 };
            System.Threading.ThreadPool.GetAvailableThreads(out AvailableThreads[0], out AvailableThreads[1]);
            String UpdateProgress = "Computers completed: " + IntDone + Environment.NewLine +
                "SQL computers completed: " + IntSQL + Environment.NewLine +
                "Servers completed: " + IntServer + Environment.NewLine +
                "Port scans completed: " + IntPort + Environment.NewLine +
                "Currently working on: " + CurrentComputer + Environment.NewLine +
                "Total computers: " + ServerList.Count + Environment.NewLine +
                (IntScanType == 4 ? "Total domains: " + ScanAD.DomainList.Count + Environment.NewLine : "") +
                "Concurrent work items: " + (MaxThreads[0] - AvailableThreads[0]) + "/" + MaxThreads[0];
            Tscan.Scan.ProgressForm.ProgressLabel.Invoke((MethodInvoker)(() =>
                Tscan.Scan.ProgressForm.ProgressLabel.Text = UpdateProgress));
            Tscan.Scan.ProgressForm.progressBarTotal.Invoke((MethodInvoker)(() =>
                Tscan.Scan.ProgressForm.progressBarTotal.Value = IntDone / ServerList.Count * 100));
        }
        /// <summary>
        /// This method requests threaded scans for globs of 10 servers each
        /// </summary>
        /// 
        public void ScanNetWorkItem(Object ProgressLabel)
        {
            Int16 SubsetSize = 100;
            String[] SubsetServerList = new String[SubsetSize];
            //test[1] = "str";
            SubsetServerList[0] = "Empty";
            RemoteExec.CompileService();
            BuildServerList();
            String[] ServerListArray;
            int[] AvailableThreads = { 0, 0 };
            for (int k = 0; k < 15; k++)
            {
                ServerListArray = new String[ServerList.Count];
                ServerList.Keys.CopyTo(ServerListArray, 0);
                for (Int32 i = 0; i <= ServerListArray.Count(); i += SubsetSize)
                {
                    SubsetServerList = new String[SubsetSize];
                    for (int j = 0; j < SubsetSize && i + j < ServerListArray.Count(); j++)
                    { SubsetServerList[j] = ServerListArray[i + j]; }
                    System.Threading.ThreadPool.QueueUserWorkItem(
                        new System.Threading.WaitCallback(Tscan.Scan.ScanHundredServers), SubsetServerList);
                    AreResourcesAvailable();
                    UpdateProgress(SubsetServerList[0] + " #" + i);
                    System.Threading.ThreadPool.GetAvailableThreads(
                        out AvailableThreads[0], out AvailableThreads[1]);
                    while (AvailableThreads[0] == 0)
                    {
                        System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                        AreResourcesAvailable();
                        UpdateProgress(SubsetServerList[0] + " #" + i);
                        System.Threading.ThreadPool.GetAvailableThreads(
                            out AvailableThreads[0], out AvailableThreads[1]);
                    }
                }
                for (Int32 i = 0; i < 60 * 8; i++)
                {
                    System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                    AreResourcesAvailable();
                    UpdateProgress("8 Hour Wait. " + k + "/15");
                    if (IntDone >= ServerList.Count * 0.998) Application.Exit();
                }
                IntPort = 0;
            }
            //return 0;
        }
        /// <summary>
        /// This scans ten servers
        /// </summary>
        /// 
        public void ScanHundredServers(Object SubsetServerList)
        {
            //String[] str = 
            //String[] str = ((System.Collections.IEnumerable)SubsetServerList).Cast<object>()
            //    .Select(x => (x!=null?x.ToString():null)).ToArray();
            Int16 SubsetSize = 10;
            Int16 i = 0;
            String[] ServerListArray;
            ServerListArray = new String[SubsetSize];
            foreach (String Server in (System.Collections.IEnumerable)SubsetServerList)
            {
                ServerListArray[i] = Server;
                i++;
                if (i == SubsetSize)
                {
                    System.Threading.ThreadPool.QueueUserWorkItem(
                        new System.Threading.WaitCallback(Tscan.Scan.ScanTenServers), ServerListArray);
                    //ScanTenServers(ServerListArray);
                    ServerListArray = new String[SubsetSize];
                    i = 0;
                }
            }
        }
        /// <summary>
        /// This scans ten servers
        /// </summary>
        /// 
        public void ScanTenServers(Object SubsetServerList)
        {
            //String[] str = 
            //String[] str = ((System.Collections.IEnumerable)SubsetServerList).Cast<object>()
            //    .Select(x => (x!=null?x.ToString():null)).ToArray();
            String Filename = "";
            System.Collections.Concurrent.ConcurrentDictionary<String, String> Output = new System.Collections.Concurrent.ConcurrentDictionary<String, String>();
            foreach (String Server in (System.Collections.IEnumerable)SubsetServerList)
            {
                ScanServer(Server, Output);
                Filename += Server + ",";
            }
            foreach (String Object in Output.Keys)
            {
                WriteToDisk(Filename.TrimEnd(",".ToCharArray()) + "_" + Object + ".csv", Output[Object]);
            }
        }
        /// <summary>
        /// This tries to scan using HTTP Headers
        /// </summary>
        /// 
        public Boolean HTTPHeaderScan(String Server, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output)
        {
            String[] Ports = { "80", "443", "8080", "8008", "8443" };
            foreach (String Port in Ports)
            {
                String StringTable = "";
                String StringHeader = "";
                String StringRow = "";
                Boolean HeaderDone = false;
                System.Net.HttpWebRequest Req;
                if (Port.Contains("443") || Port.Equals("443", StringComparison.CurrentCultureIgnoreCase))
                {
                    Req = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(
                    "https://" + Server + ":" + Port);
                }
                else
                {
                    Req = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(
                    "http://" + Server + ":" + Port);
                }
                System.Net.HttpWebResponse Resp;
                try
                {
                    Resp = (System.Net.HttpWebResponse)Req.GetResponse();
                    StringRow = "\"" + Server + "\",";
                    StringHeader = "Computer,";
                    foreach (String Key in Resp.Headers.AllKeys)
                    {
                        try
                        {
                            StringRow += "\"" + Resp.Headers[Key] + "\",";
                        }
                        catch
                        {
                            StringRow += "\"\",";
                        }
                        StringHeader += "\"" + Key + "\",";
                    }
                    if (!HeaderDone) StringTable = StringHeader + Environment.NewLine;
                    HeaderDone = true;
                    StringTable += StringRow + Environment.NewLine;
                    Resp.Close();
                    //WriteToDisk(Server + "_" + Port + "_Header.csv", StringTable);
                    if (Output.ContainsKey("Header"))
                    {
                        Output["Header"] += StringTable;
                    }
                    else
                    {
                        Output.TryAdd("Header", StringTable);
                    }
                }
                catch //(System.Net.WebException e)
                {

                }
            }
            return true;
        }
        /// <summary>
        /// This tries to scan using SMB Headers
        /// </summary>
        /// 
        public Boolean SMBHeaderScan(String Server, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output)
        {
            String StringTable = "";
            String StringHeader = "";
            String StringRow = "";
            Boolean HeaderDone = false;
            System.Net.FileWebRequest Req =
                (System.Net.FileWebRequest)System.Net.FileWebRequest.Create("//" + Server + "/admin$/notepad.exe");
            System.Net.FileWebResponse Resp;
            try
            {
                Resp = (System.Net.FileWebResponse)Req.GetResponse();
                StringRow = "\"" + Server + "\",";
                StringHeader = "Computer,";
                foreach (String Key in Resp.Headers.AllKeys)
                {
                    try
                    {
                        StringRow += "\"" + Resp.Headers[Key] + "\",";
                    }
                    catch
                    {
                        StringRow += "\"\",";
                    }
                    StringHeader += "\"" + Key + "\",";
                }
                if (!HeaderDone) StringTable = StringHeader + Environment.NewLine;
                HeaderDone = true;
                StringTable += StringRow + Environment.NewLine;
                Resp.Close();
            }
            catch (System.Net.WebException)
            {
                return true;
            }
            //WriteToDisk(Server + "_SMBHeader.csv", StringTable);
            if (Output.ContainsKey("SMBHeader"))
            {
                Output["SMBHeader"] += StringTable;
            }
            else
            {
                Output.TryAdd("SMBHeader", StringTable);
            }
            return true;
        }
        /// <summary>
        /// This icmp pings, syn pings 20 ports, and arp pings to get the MAC vendor for ping.csv
        /// </summary>
        /// 
        public Boolean PortScan(String Server, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output)
        {
            //ICMP - Broadcast, IP, Mac
            //Syn - Port, State, Service, Version
            //Nbtstat - Name, User, Mac
            //SMB - OS
            String Header = "";
            String Values = "";
            String Table = "";
            Byte[] MacAddressBytes;
            String Mac;
            Int16[] ListOfPorts = {53, //DNS
                                  80, //HTTP
                                  135, //WMI
                                  137,138,139, //NetBIOS
                                  389, //LDAP
                                  443, //HTTPS
                                  445, //SMB
                                  1433,1434, //SQL
                                  5060,5061, //SIP
                                  5431, //UPNP
                                  8008,8080,8443, //HTTP
                                  9100,9220 //PCL
                                  };
            Header = "Computer,";
            Values = "\"" + Server + "\",";
            try
            {
                System.Net.NetworkInformation.PingReply PR = new System.Net.NetworkInformation.Ping().Send(Server);
                Values += "\"" + PR.RoundtripTime + "\",";
                Header += "\"" + "PingTime" + "\",";
                Values += "\"" + PR.Status + "\",";
                Header += "\"" + "PingStatus" + "\",";
                Values += "\"" + ((PR.Options != null) ? PR.Options.Ttl.ToString() : "null") + "\",";
                Header += "\"" + "TTL" + "\",";
            }
            catch (System.Net.NetworkInformation.PingException e)
            {
                Values += "\"" + 0 + "\",";
                Header += "\"" + "PingTime" + "\",";
                Values += "\"" + e.Message + "\",";
                Header += "\"" + "PingStatus" + "\",";
                Values += "\"" + 0 + "\",";
                Header += "\"" + "TTL" + "\",";
            }
            foreach (Int16 IntPort in ListOfPorts)
            {
                Values += "\"" + SinglePort(Server, IntPort) + "\",";
                Header += "\"" + IntPort + "\",";
            }
            Header += "\"Mac\",\"Details\",";
            System.Net.IPAddress ipAddress = System.Net.IPAddress.Parse("0.0.0.0");
            Boolean Fail = false;
            try
            {
                Int16 Skip = 0x0;
                if (Server.Split(".".ToCharArray()).Count() == 4 &&
                Int16.TryParse(Server.Split(".".ToCharArray())[0], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[1], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[2], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[3], out Skip))
                {
                    //if server is IP
                    ipAddress = System.Net.IPAddress.Parse(Server);
                }
                else
                {
                    //if server is hostname
                    ipAddress = System.Net.Dns.GetHostEntry(Server).AddressList[0];
                }
            }
            catch
            {
                Fail = true;
            }
            if (!Fail)
            {
                uint UintAddress = BitConverter.ToUInt32(ipAddress.GetAddressBytes(), 0);
                uint MacAddressByteLength = 6;
                MacAddressBytes = new Byte[MacAddressByteLength];
                int SendARPSuccess = SendARP(UintAddress, 0, MacAddressBytes, ref MacAddressByteLength);
                if (SendARPSuccess == 0)
                {
                    Values += "\"";
                    Mac = "";
                    for (int i = 0; i < MacAddressByteLength; i++)
                    {
                        if (!String.IsNullOrEmpty(MacAddressBytes[i].ToString("x2")))
                            Mac += MacAddressBytes[i].ToString("x2");
                        else Mac += "--";
                        if (i < MacAddressByteLength - 1) Mac += ":";
                    }
                    Values += Mac;
                    Values += "\",";
                    Values += "\"";
                    Values += MACLookup(Mac);
                    Values += "\",";
                }
                else
                {
                    Values += "\"ARP Fail\",\"\",";
                }
            }
            else
            {
                Values += "\"DNS Fail\",\"\",";
            }
            Table = Header + Environment.NewLine + Values;
            //WriteToDisk(Server + "_Ping.csv", Table);
            if (Output.ContainsKey("SMBHeader"))
            {
                Output["Ping"] += Table;
            }
            else
            {
                Output.TryAdd("Ping", Table);
            }

            return true;
        }
        /// <summary>
        /// This looks up a MAC to it's vendor only. Runs 200 times an hour.
        /// </summary>
        /// 
        public String MACLookup(String MAC)
        {
            //https://api.macvendors.co/'MAC'/xml
            //https://api.macvendors.com/'MAC'
            System.Net.HttpWebRequest Req =
                (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(MACLookupURI.Replace("'MAC'", MAC));
            System.Net.HttpWebResponse Resp;
            String StringResponse = "";
            try
            {
                Resp = (System.Net.HttpWebResponse)Req.GetResponse();
                System.IO.Stream Streamer = Resp.GetResponseStream();
                System.IO.StreamReader StreamRead = new System.IO.StreamReader(Streamer);
                StringResponse = StreamRead.ReadToEnd();
                StreamRead.Close();
                Resp.Close();
            }
            catch (System.Net.WebException e)
            {
                StringResponse = e.Message;
            }
            //            StringResponse = @"<result>
            //<company>Apple, Inc.</company>
            //<mac_prefix>08:74:02</mac_prefix>
            //<address>1 Infinite Loop,Cupertino CA 95014,US</address>
            //<start_hex>087402000000</start_hex>
            //<end_hex>087402FFFFFF</end_hex>
            //<country>US</country>
            //<type>MA-L</type>
            //</result>";
            if (StringResponse.Contains("json"))
            {
                //system.runtime.serialization json .net 4.0
                //System.Runtime.Serialization.json
            }
            else if (StringResponse.Contains("</"))
            {

                //system.xml xml
                System.Xml.XmlDocument Doc = new System.Xml.XmlDocument();
                Doc.LoadXml(StringResponse);
                //XMLElements
                System.Xml.XmlElement OneElement = null;
                foreach (String ElementName in XMLElements)
                {
                    if (OneElement == null)
                    {
                        OneElement = Doc[ElementName];
                    }
                    else
                    {
                        OneElement = OneElement[ElementName];
                    }
                }
                StringResponse = ScrubString(OneElement.InnerText.ToString());
            }
            else
            {
                StringResponse = ScrubString(StringResponse);
            }
            return StringResponse;
        }
        /// <summary>
        /// This scrubs a string of comma, quote, space
        /// </summary>
        /// 
        public String ScrubString(String String)
        {
            if (String.IsNullOrEmpty(String)) String = "";
            String Stripper = "[\'\"\\\n\0\xe\x1\x7F\a\b\f\r\t\v,";
            for (uint i = 0; i < 32; i++)
            {
                Stripper += (char)i;
            }
            Stripper += "]";
            String = Regex.Replace(String, Stripper, "");
            return String;
        }
        /// <summary>
        /// This pings a single port and determines if it's open
        /// </summary>
        /// 
        public Boolean SinglePort(String Server, Int16 Port)
        {
            //Port, State, Service, Version - nmap
            //ACK,PSH,RST,SYN,FIN
            try
            {
                System.Net.Sockets.TcpClient Client = new System.Net.Sockets.TcpClient();
                Client.Connect(Server, Port);
                return Client.Connected;
            }
            catch (System.Net.Sockets.SocketException)
            {
                //MessageBox.Show(e.Message);//SocketException is common for offline machines
                return false;
            }
        }
        /// <summary>
        /// This sets up the WMI scope
        /// </summary>
        /// 
        public System.Management.ManagementScope SetupScope(String Server, String Domain, String User, String Pass)
        {
            System.Management.ManagementScope Scope = new System.Management.ManagementScope();
            Scope = new System.Management.ManagementScope("\\\\" + Server + "\\root\\cimv2");
            Scope.Options.Authentication = System.Management.AuthenticationLevel.Packet;
            Scope.Options.EnablePrivileges = true;
            Scope.Options.Impersonation = System.Management.ImpersonationLevel.Impersonate;
            Scope.Options.Locale = "MS_409";
            Scope.Options.Timeout = TimeSpan.FromMinutes(10);
            if (User == "" && Pass == "")
            {
            }
            else if (Server.Equals(Domain, StringComparison.CurrentCultureIgnoreCase))
            {
                Scope.Options.Password = Pass;
                Scope.Options.Username = Domain + "\\" + User;
            }
            else
            {
                Scope.Options.Password = Pass;
                Scope.Options.Username = User;
                Scope.Options.Authority = Domain;
            }
            return Scope;
        }
        /// <summary>
        /// This determines if a username and password are valid
        /// </summary>
        /// 
        public Int16 TestPassword(String Server, String Domain, String User, String Pass)
        {
            String Table = "";
            String OSQuery = "Select * from win32_operatingsystem";
            System.Management.ManagementScope Scope = SetupScope(Server, Domain, User, Pass);
            try
            {
                Scope.Connect();
            }
            catch (Exception f)
            {
                if (f.Message == "The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)") return 2;
                return 0;
            }
            System.Management.ObjectQuery Query = new System.Management.ObjectQuery(OSQuery);
            System.Management.ManagementObjectSearcher Searcher =
                new System.Management.ManagementObjectSearcher(Scope, Query);
            try
            {
                System.Management.ManagementObjectCollection Result = Searcher.Get();
                if (Result.Count == 0) return 0;
            }
            catch (Exception f)
            {
                if (f.Message == "The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)") return 2;
                return 0;
            }
            if (DoPass && !String.IsNullOrEmpty(User))
            {
                Table = "Computer,\"Domain\",\"Username\",\"Password\"" + Environment.NewLine +
                    "\"" + Server + "\",\"" + Domain + "\",\"" + User + "\",\"" + Pass + "\"";
                WriteToDisk(Server + "_Password.csv", Table);
            }
            return 1;
        }
        /// <summary>
        /// This collects a csv from a single WMI Object formatted as a table
        /// </summary>
        /// 
        public Boolean SingleWMITable(String Server, String Domain, String Object, String User, String Pass,
        String Namespace, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output)
        {
            String OSQuery = "Select * from " + Object;
            System.Management.ManagementScope Scope = SetupScope(Server, Domain, User, Pass);
            Scope.Path = new System.Management.ManagementPath("\\\\" + Server + "\\" + Namespace);
            try
            {
                Scope.Connect();
            }
            catch
            {
                return false;
            }
            System.Management.ObjectQuery Query = new System.Management.ObjectQuery(OSQuery);
            System.Management.ManagementObjectSearcher Searcher =
                new System.Management.ManagementObjectSearcher(Scope, Query);
            String Names = "";
            String Values = "";
            String Table = "";
            Boolean HeaderDone = false;
            Boolean RemoteExecDone = false;
            System.Management.ManagementObjectCollection Result;
            try
            {
                Result = Searcher.Get();
                if (Result.Count == 0 &&
                    !Object.StartsWith("msvm", StringComparison.CurrentCultureIgnoreCase) &&
                    !Object.Equals("win32_quickfixengineering", StringComparison.CurrentCultureIgnoreCase)) return false;
            }
            catch
            {
                return false;
            }
            try
            {
                foreach (System.Management.ManagementBaseObject Row in Result)
                {
                    Names = "Computer,";
                    Values = "\"" + Server + "\",";
                    foreach (System.Management.PropertyData Cell in Row.Properties)
                    {
                        Names += "\"" + Cell.Name + "\",";
                        if (Cell.Value != null)
                        {
                            String CellValue = "";
                            if (Cell.Value.ToString().Equals("System.String[]") ||
                                Cell.Value.ToString().Equals("System.UInt16[]"))
                            {
                                String[] CellArray = ((System.Collections.IEnumerable)Cell.Value).Cast<object>()
                                    .Select(x => (x != null ? x.ToString() : null)).ToArray();
                                if (CellArray.Count() < 10)
                                    foreach (String CellArrayValue in CellArray)
                                        CellValue += CellArrayValue + " ";
                                else CellValue = Cell.Value.ToString();
                            }
                            else CellValue = Cell.Value.ToString();
                            Values += "\"" + ScrubString(CellValue) + "\",";
                            if (SearchObjects.ToLower().Contains(Object.ToLower()))
                            {
                                foreach (String FindWord in SearchTerm.Split(",".ToCharArray()))
                                {
                                    if (FindWord.Length > 2
                                        && ScrubString(CellValue).ToLower().Contains(FindWord.ToLower())
                                        && !RemoteExecDone)
                                        RemoteExecDone = RemoteExec.RemoteExec(Server, Domain, User, Pass);
                                }
                                if (Cell.Name.Equals("Name", StringComparison.CurrentCultureIgnoreCase)
                                    && Object.Equals("win32_operatingsystem", StringComparison.CurrentCultureIgnoreCase)
                                    && ScrubString(CellValue).ToLower().Contains("windows server"))
                                    IntServer++;
                                if (Cell.Name.Equals("DNSServerSearchOrder", StringComparison.CurrentCultureIgnoreCase)
                                    && Object.Equals("win32_networkadapterconfiguration", StringComparison.CurrentCultureIgnoreCase)
                                    && !String.IsNullOrWhiteSpace(ScrubString(CellValue))
                                    && (Cell.Value.ToString().Equals("System.String[]")
                                    || Cell.Value.ToString().Equals("System.UInt16[]")))
                                    foreach (String CellArrayValue in ((System.Collections.IEnumerable)Cell.Value).Cast<object>())
                                        ServerList.TryAdd(CellArrayValue, "");
                            }
                        }
                        else
                        {
                            Values += "\"\",";
                        }
                    }
                    if (IntScanType == 3 &&
                            Object.Equals("win32_useraccount", StringComparison.CurrentCultureIgnoreCase) &&
                            Row.GetPropertyValue("LocalAccount").ToString().Equals("False",
                            StringComparison.CurrentCultureIgnoreCase) &&
                            Row.GetPropertyValue("Disabled").ToString().Equals("False",
                            StringComparison.CurrentCultureIgnoreCase) &&
                            !Tscan.Scan.ScanAD.DomainAdminList.ContainsKey(Row.GetPropertyValue("Domain") + "\\" +
                            Row.GetPropertyValue("Name"))
                            )
                    {
                        foreach (String WMIPass in Tscan.Scan.WMIPasswords)
                        {
                            if (DoPass && TestPassword(Server,
                                Row.GetPropertyValue("Domain").ToString(),
                                Row.GetPropertyValue("Name").ToString(),
                                WMIPass).Equals(1))
                            {
                                Tscan.Scan.ScanAD.DomainAdminList.TryAdd(Row.GetPropertyValue("Domain") + "\\" +
                                    Row.GetPropertyValue("Name"), WMIPass);
                                MessageBox.Show("Found password for " + Row.GetPropertyValue("Name"));
                                break;
                            }
                        }
                        if (!Tscan.Scan.ScanAD.DomainAdminList.ContainsKey(Row.GetPropertyValue("Domain") + "\\" +
                            Row.GetPropertyValue("Name")))
                            Tscan.Scan.ScanAD.DomainAdminList.TryAdd(Row.GetPropertyValue("Domain") + "\\" +
                                Row.GetPropertyValue("Name"), "fail");
                    }
                    if (!HeaderDone) Table += Names + Environment.NewLine;
                    Table += Values + Environment.NewLine;
                    HeaderDone = true;
                }
            }
            catch (System.Runtime.InteropServices.COMException e)
            {
                MessageBox.Show(Server + " " + Object + " " + e.Message);
            }
            //WriteToDisk(Server + "_" + Object + ".csv", Table);
            if (Output.ContainsKey(Object))
            {
                Output[Object] += Table;
            }
            else
            {
                Output.TryAdd(Object, Table);
            }
            if (String.IsNullOrEmpty(Table) &&
                    !Object.StartsWith("msvm", StringComparison.CurrentCultureIgnoreCase) &&
                    !Object.Equals("win32_quickfixengineering", StringComparison.CurrentCultureIgnoreCase)) return false;
            else return true;
        }
        /// <summary>
        /// This scans a single server
        /// </summary>
        /// 
        public void ScanServer(String Server, System.Collections.Concurrent.ConcurrentDictionary<String, String> Output)
        {
            Boolean Success = true;
            Int16 Skip = 0x0;
            String UserSuccess = "";
            String PassSuccess = "";
            String DomainSuccess = "";
            String ServerOriginal = Server;
            //the next line may face problems with dhcp on Class C networks
            if (String.IsNullOrEmpty(Server)) return;
            if (ServerList[Server].Equals("Done", StringComparison.CurrentCultureIgnoreCase) &&
                IntScanType != 3 && !(Server.Split(".".ToCharArray()).Count() == 4 &&
                Int16.TryParse(Server.Split(".".ToCharArray())[0], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[1], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[2], out Skip) &&
                Int16.TryParse(Server.Split(".".ToCharArray())[3], out Skip))) return;
            String ServerResolution = Resolve(Server);
            if (String.IsNullOrEmpty(ServerResolution)) return;
            Server = ServerResolution;
            try
            {
                if (System.IO.File.Exists(System.IO.Path.Combine(
                    Environment.CurrentDirectory, Server + "_" + "Done" + ".txt")))
                {
                    ServerList[ServerOriginal] = "Done";
                    return;
                }
            }
            catch
            {
                return;
            }
            //PortScan(Server);
            try
            {
                if (IntScanType == 3 &&
                    Server.Split(".".ToCharArray()).Count() == 4 &&
                    Int16.TryParse(Server.Split(".".ToCharArray())[0], out Skip) &&
                    Int16.TryParse(Server.Split(".".ToCharArray())[1], out Skip) &&
                    Int16.TryParse(Server.Split(".".ToCharArray())[2], out Skip) &&
                    Int16.TryParse(Server.Split(".".ToCharArray())[3], out Skip) &&
                    //!new System.Net.NetworkInformation.Ping().Send(Server).Status.Equals("Success") &&
                    String.IsNullOrWhiteSpace(System.Net.Dns.GetHostEntry(Server).HostName))
                //TestPassword(Server, "", "", "").Equals(2))
                {
                    //if (PortScan(Server)) IntPort++;
                    //skip if scanning subnet, resolve failed, ping failed, and wmi port is closed or firewalled
                    return;
                }
            }
            catch { return; }

            if (Server.Equals(Environment.MachineName, StringComparison.CurrentCultureIgnoreCase))
            {
                UserSuccess = "";
                PassSuccess = "";
            }
            else if (TestPassword(Server, "", "", "").Equals(1))
            {
                UserSuccess = "";
                PassSuccess = "";
            }
            else if (TestPassword(Server, Server, Environment.UserName, Password).Equals(1))
            {
                //likely to fail due to server as authority
                DomainSuccess = Server;
                UserSuccess = Environment.UserName;
                PassSuccess = Password;
            }
            else if (TestPassword(Server, Environment.UserDomainName, Environment.UserName, Password).Equals(1))
            {
                DomainSuccess = Environment.UserDomainName;
                UserSuccess = Environment.UserName;
                PassSuccess = Password;
            }
            else
            {
                foreach (String User in WMIUsernames)
                {
                    foreach (String Pass in WMIPasswords)
                    {
                        if (DoPass && TestPassword(Server, Server, User, Pass).Equals(1))
                        {
                            DomainSuccess = Server;
                            UserSuccess = User;
                            PassSuccess = Pass;
                            break;
                        }
                    }
                    if (!String.IsNullOrEmpty(UserSuccess)) break;
                }
                if (String.IsNullOrEmpty(UserSuccess))
                {
                    foreach (String Key in ScanAD.DomainAdminList.Keys)
                    {
                        if (ScanAD.DomainAdminList[Key].Equals("fail") &&
                            DoPass && TestPassword(Server,
                            Key.Split("\\".ToCharArray())[0],
                            Key.Split("\\".ToCharArray())[1],
                            ScanAD.DomainAdminList[Key]).Equals(1))
                        {
                            DomainSuccess = Key.Split("\\".ToCharArray())[0];
                            UserSuccess = Key.Split("\\".ToCharArray())[1];
                            PassSuccess = ScanAD.DomainAdminList[Key];
                            break;
                        }
                    }
                }
            }
            if (!String.IsNullOrEmpty(UserSuccess))
            {
                WriteToDisk(Server + "_Password.csv",
                            "Computer,\"Domain\",\"User\",\"Pass\"" + Environment.NewLine +
                            "\"" + Server +
                            "\",\"" + DomainSuccess + "\",\"" + UserSuccess + "\",\"" + PassSuccess + "\"");
            }
            String[] WMIObjects = {"win32_product", "win32_quickfixengineering", //Software
                                  "win32_service", "win32_operatingsystem", //Software
                                  "win32_networkadapterconfiguration", "win32_processor", //HW
                                  "win32_computersystem", "win32_systemenclosure", "win32_diskdrive", //HW
                                  "win32_systemusers", "win32_useraccount", //user
                                  "win32_groupuser", "win32_loggedonuser", //user
                                  "win32_osrecoveryconfiguration", "win32_ntdomain", //sundry
                                  "win32_perfformatteddata_perfnet_serverworkqueues", //perf
                                  "win32_perfformatteddata_perfos_processor",  //perf
                                  "win32_perfformatteddata_perfos_memory"}; //perf
            List<String> WMIObjectsList = WMIObjects.ToList();
            foreach (String WMIObject in SearchObjects.Split(",".ToCharArray()))
            {
                if (!WMIObjectsList.Contains(WMIObject.ToLower()))
                {
                    WMIObjectsList.Add(WMIObject.ToLower());
                }
            }
            WMIObjects = WMIObjectsList.ToArray();
            foreach (String WMIObject in WMIObjects)
            {
                if (SingleWMITable(Server,
                    DomainSuccess,
                    WMIObject,
                    UserSuccess,
                    PassSuccess,
                    "root\\cimv2",
                    Output) && Success)
                    Success = true;
                else Success = false;
            }
            String[] SQLNamespaces = {"root\\Microsoft\\SqlServer\\ComputerManagement\\MSSQLSERVER",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement10\\MSSQLSERVER",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement12\\MSSQLSERVER",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement14\\MSSQLSERVER",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement10",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement12",
                                      "root\\Microsoft\\SqlServer\\ComputerManagement14"};
            Boolean BoolSQL = false;
            foreach (String SQLNamespace in SQLNamespaces)
            {
                if (SingleWMITable(Server,
                    DomainSuccess,
                    "SqlServiceAdvancedProperty",
                    UserSuccess,
                    PassSuccess,
                    SQLNamespace,
                    Output))
                    BoolSQL = true;
            }
            if (BoolSQL) IntSQL++;
            //5/6 complete
            String[] MSVMObjects = { "msvm_computersystem", "msvm_processor", "msvm_diskdrive",
                                       "msvm_summaryinformation", "msvm_guestnetworkadapterconfiguration",
                                       "msvm_syntheticethernetportsettingdata" };
            WMIObjectsList = MSVMObjects.ToList();
            foreach (String WMIObject in SearchObjects.Split(",".ToCharArray()))
            {
                if (!WMIObjectsList.Contains(WMIObject.ToLower()))
                {
                    WMIObjectsList.Add(WMIObject.ToLower());
                }
            }
            MSVMObjects = WMIObjectsList.ToArray();
            foreach (String WMIObject in MSVMObjects)
            {
                SingleWMITable(Server,
                    DomainSuccess,
                    WMIObject,
                    UserSuccess,
                    PassSuccess,
                    "root\\virtualization\\v2",
                    Output);
            }
            foreach (String WMIObject in MSVMObjects)
            {
                SingleWMITable(Server,
                    DomainSuccess,
                    WMIObject,
                    UserSuccess,
                    PassSuccess,
                    "root\\virtualization",
                    Output);
            }
            if (PortScan(Server, Output) && Success) Success = true;
            else Success = false;
            if (SMBHeaderScan(Server, Output) && Success) Success = true;
            else Success = false;
            if (HTTPHeaderScan(Server, Output) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                Output,
                true) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninst‌​all",
                Output,
                true) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDump(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                Output,
                true) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninst‌​all",
                Output,
                true) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
                Output,
                false) && Success) Success = true;
            else Success = false;
            if (RegistryDumpAdvapi(Server,
                RegistryHive.LocalMachine,
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
                Output,
                false) && Success) Success = true;
            else Success = false;
            //I think port scan has only true return paths lol
            if (Success)
            {
                ServerList[ServerOriginal] = "Done";
                IntDone++;
                WriteToDisk(Server + "_Done.txt",
                            "Computer,Done" + Environment.NewLine + Server + "," + DateTime.Now.ToString());
            }
            else
            {
                WriteToDisk(Server + "_Fail.txt",
                            "Computer,Fail" + Environment.NewLine + Server + "," + DateTime.Now.ToString());
            }
        }
        /// <summary>
        /// This resolves a single host. Sometimes this is an indicator of existance.
        /// </summary>
        /// 
        public String Resolve(String Server)
        {
            String HostName = "";
            System.Net.IPHostEntry Host = new System.Net.IPHostEntry();
            try
            {
                Host = System.Net.Dns.GetHostEntry(Server);
                HostName = Host.HostName;
            }
            catch
            {
                return Server;
            }
            return HostName;
        }
        /// <summary>
        /// This builds a server list based on selections in ScanType.cs form.
        /// </summary>
        /// 
        public void BuildServerList()
        {
            if (IntScanType == 1)
            {
                ServerList.TryAdd(Environment.MachineName, "");
            }
            else if (IntScanType == 2)
            {
                if (String.IsNullOrEmpty(ServerListFilename))
                    ServerListFilename =
                        System.IO.Path.Combine(Environment.CurrentDirectory, "Serverlist.txt");
                if (!System.IO.File.Exists(ServerListFilename))
                {
                    WriteToDisk(ServerListFilename, Environment.MachineName);
                }
                foreach (String Server in System.IO.File.ReadAllLines(ServerListFilename))
                {
                    ServerList.TryAdd(Server, "");
                }

            }
            else if (IntScanType == 3)
            {
                String Subnet = "";
                String MyIP = "";
                foreach (System.Net.NetworkInformation.NetworkInterface Interface in
                    System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (System.Net.NetworkInformation.UnicastIPAddressInformation Address in
                        Interface.GetIPProperties().UnicastAddresses)
                    {
                        if (Interface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Down &&
                            Address.IPv4Mask != null && "0.0.0.0" != Address.IPv4Mask.ToString() &&
                            !Address.Address.ToString().StartsWith("127", StringComparison.CurrentCultureIgnoreCase))
                        {
                            Subnet = Address.IPv4Mask.ToString();
                            MyIP = Address.Address.ToString();

                        }
                    }
                }
                String[] SubnetArray = Subnet.Split(".".ToCharArray());
                String[] MyIPArray = MyIP.Split(".".ToCharArray());
                if (SubnetArray[3] == "0" || SubnetArray[3] == "240")
                {
                    for (int a = 1; a <= 255; a++)
                    {
                        for (int b = 0; b <= 255; b++)
                        {
                            for (int c = 0; c <= 255; c++)
                            {
                                for (int d = 1; d <= 254; d++)
                                {
                                    if (ScanInternet)
                                    {
                                        if (!(a == 10 ||
                                            (a == 172 && (b >= 16 && b <= 31)) ||
                                            (a == 192 && b == 168)))//169, 127?
                                        {
                                            ServerList.TryAdd(a.ToString() + "." + b + "." + c + "." + d, "");
                                            if (c == 0 && d == 0) UpdateProgress(a.ToString() + "." + b + "." +
                                                c + "." + d);
                                        }
                                        //Internet, I recommend 300GB of memory for the serverlist
                                        //Pioneer 199.0.0.0
                                        //4b addresses in 10 hours
                                    }
                                    else if (SubnetArray[0] == "0")
                                    {
                                        ServerList.TryAdd(a.ToString() + "." + b + "." + c + "." + d, "");
                                        if (c == 0 && d == 0) UpdateProgress(a.ToString() + "." + b + "." +
                                            c + "." + d);
                                        //no gateway, 169.254.0.1 4b addresses in 10 hours
                                    }
                                    else if (SubnetArray[1] == "0" && SubnetArray[0] == "255")
                                    {
                                        ServerList.TryAdd(MyIPArray[0] + "." + b + "." + c + "." + d, "");
                                        if (c == 0 && d == 0) UpdateProgress(MyIPArray[0] + "." + b + "." +
                                            c + "." + d);
                                        //c 10.0.0.1 16m addresses in 2 minutes
                                    }
                                    else if (SubnetArray[2] == "0" && SubnetArray[1] == "255")
                                    {
                                        ServerList.TryAdd(MyIPArray[0] + "." + MyIPArray[1] + "." +
                                            c + "." + d, "");
                                        //b 172.16.0.1 65k addresses in seconds
                                    }
                                    else if (SubnetArray[3] == "0" && SubnetArray[2] == "255")
                                    {
                                        ServerList.TryAdd(MyIPArray[0] + "." + MyIPArray[1] + "." +
                                            MyIPArray[2] + "." + d, "");
                                        //a 192.168.1.1 256 addresses built in seconds
                                    }
                                    else if (SubnetArray[3] != "255" && SubnetArray[3] != "0")
                                    {
                                        if ((d & Int16.Parse(SubnetArray[3])) ==
                                            (Int16.Parse(MyIPArray[3]) & Int16.Parse(SubnetArray[3])))
                                        {
                                            ServerList.TryAdd(MyIPArray[0] + "." + MyIPArray[1] + "." +
                                                MyIPArray[2] + "." + d, "");
                                        }
                                    }
                                    else if (SubnetArray[2] != "255" && SubnetArray[2] != "0")
                                    {
                                        if ((c & Int16.Parse(SubnetArray[2])) ==
                                            (Int16.Parse(MyIPArray[2]) & Int16.Parse(SubnetArray[2])))
                                        {
                                            ServerList.TryAdd(MyIPArray[0] + "." + MyIPArray[1] + "." + c + "." + d, "");
                                        }
                                    }
                                    else if (SubnetArray[1] != "255" && SubnetArray[1] != "0")
                                    {
                                        if ((b & Int16.Parse(SubnetArray[1])) ==
                                            (Int16.Parse(MyIPArray[1]) & Int16.Parse(SubnetArray[1])))
                                        {
                                            ServerList.TryAdd(MyIPArray[0] + "." + b + "." + c + "." + d, "");
                                        }
                                    }
                                    else ServerList.TryAdd(MyIP, "");
                                    if (SubnetArray[3] == "255" && !ScanInternet) break;
                                }
                                if (SubnetArray[2] == "255" && !ScanInternet) break;
                            }
                            if (SubnetArray[1] == "255" && !ScanInternet) break;
                        }
                        if (SubnetArray[0] == "255" && !ScanInternet) break;
                    }
                }
            }
            else if (IntScanType == 4)
            {
                Boolean ADAvailable = true;
                try
                {
                    //get user domain
                    System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch
                {
                    //if user authority isn't a domain then disable AD scans
                    //this.ActiveDirectory.Enabled = false;
                    //this.ADOnly.Enabled = false;
                    ADAvailable = false;
                }
                if (ADAvailable)
                {
                    ScanAD.ScanAdmins();
                    ScanAD.ScanActiveDirectory();
                }
                else
                {
                    ScanAD.ScanWinsAndSql();
                    if (ADOnly)
                    {
                        System.IO.File.WriteAllText("Serverlist.txt", "");
                        foreach (String Key in ServerList.Keys)
                            System.IO.File.AppendAllText("Serverlist.txt", Key + Environment.NewLine);
                    }
                }
                if (ADOnly) Application.Exit();
            }
            System.IO.File.WriteAllText("Serverlist.txt", "");
            Int64 i = 0;
            String ServerListSubset = "";
            foreach (String Key in ServerList.Keys)
            {
                i++;
                if (i % 1000 == 0)
                {
                    System.IO.File.AppendAllText("Serverlist.txt", ServerListSubset);
                    ServerListSubset = "";
                }
                else
                {
                    ServerListSubset = ServerListSubset + Key + Environment.NewLine;
                }
            }
        }
    }
}
