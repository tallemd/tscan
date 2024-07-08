using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.Sql;
using System.Data;

namespace Tscan
{
    public class ScannerActiveDirectory
    {
        public System.Collections.Concurrent.ConcurrentDictionary<String, String> DomainAdminList;
        public System.Collections.Concurrent.ConcurrentDictionary<String, String> DomainList;
        public System.Collections.Concurrent.ConcurrentDictionary<String, String> DomainInProgressList;
        //public System.Collections.Specialized.StringDictionary DomainAdminList;
        //public System.Collections.Specialized.StringDictionary DomainList;
        //public System.Collections.Specialized.StringDictionary DomainInProgressList;
        /// <summary>
        /// This instantiates a Active Directory scanning object
        /// </summary>
        /// 
        public ScannerActiveDirectory()
        {
            DomainAdminList = new System.Collections.Concurrent.ConcurrentDictionary<String, String>();
            DomainList = new System.Collections.Concurrent.ConcurrentDictionary<String, String>();
            DomainInProgressList = new System.Collections.Concurrent.ConcurrentDictionary<String, String>();
        }
        /// <summary>
        /// This builds a server list from Active Directory
        /// </summary>
        /// 
        public void ScanActiveDirectory()
        {
            int[] MaxThreads = { 0, 0 };
            int[] AvailableThreads = { 0, 0 };
            DomainList.TryAdd(Environment.UserDomainName, "0");
            Int32 OldDomainCount = 0;
            for (Int16 i = 0; i < 10; i++)
            {
                Boolean Quit = true;
                foreach (String Domain in DomainList.Keys)
                {
                    if (!DomainList[Domain].Equals("Done", StringComparison.CurrentCultureIgnoreCase))
                        Quit = false;
                }
                if (Quit && i >= 2) break;
                for (Int16 j = 0; j < 10; j++)
                {
                    OldDomainCount = DomainList.Count;
                    foreach (String Domain in DomainList.Keys)
                    {
                        System.Threading.ThreadPool.QueueUserWorkItem(
                            new System.Threading.WaitCallback(ScanTrusts), Domain);
                    }//foreach domain get trusts
                    System.Threading.ThreadPool.GetMaxThreads(
                        out MaxThreads[0], out MaxThreads[1]);
                    System.Threading.ThreadPool.GetAvailableThreads(
                        out AvailableThreads[0], out AvailableThreads[1]);
                    for (Int16 k = 0;
                        k < 10 && MaxThreads[0] - AvailableThreads[0] > 2 && DomainInProgressList.Count > 0;
                        k++)
                    {
                        Tscan.Scan.UpdateProgress("10 Minute. " + k + "/10");
                        System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                        System.Threading.ThreadPool.GetMaxThreads(
                            out MaxThreads[0], out MaxThreads[1]);
                        System.Threading.ThreadPool.GetAvailableThreads(
                            out AvailableThreads[0], out AvailableThreads[1]);
                    }
                    if (OldDomainCount == DomainList.Count) break;
                }//for up to 10 trust scans
                foreach (String Domain in DomainList.Keys)
                {
                    if (!DomainInProgressList[Domain].Equals(
                        "InProgress", StringComparison.CurrentCultureIgnoreCase) &&
                        !DomainList[Domain].Equals(
                        "Done", StringComparison.CurrentCultureIgnoreCase) &&
                        !DomainList[Domain].Equals(
                        "10", StringComparison.CurrentCultureIgnoreCase))
                    {
                        Tscan.Scan.UpdateProgress(Domain);
                        System.Threading.ThreadPool.QueueUserWorkItem(
                            new System.Threading.WaitCallback(ScanDomain), Domain);
                    }
                }
                System.Threading.ThreadPool.GetMaxThreads(
                    out MaxThreads[0], out MaxThreads[1]);
                System.Threading.ThreadPool.GetAvailableThreads(
                    out AvailableThreads[0], out AvailableThreads[1]);
                for (Int16 j = 0;
                    j < 60 && MaxThreads[0] - AvailableThreads[0] > 2 && DomainInProgressList.Count > 0;
                    j++)
                {
                    Tscan.Scan.UpdateProgress("1 Hour Wait. " + j + "/60");
                    System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
                    System.Threading.ThreadPool.GetMaxThreads(
                        out MaxThreads[0], out MaxThreads[1]);
                    System.Threading.ThreadPool.GetAvailableThreads(
                        out AvailableThreads[0], out AvailableThreads[1]);
                }
            }//for up to 10 loops of both trusts and undone domains
            //AD only stub
            System.IO.File.WriteAllText("Domainlist.txt", "");
            foreach (String Key in DomainList.Keys)
                System.IO.File.AppendAllText("Domainlist.txt", Key + Environment.NewLine);
        }
        /// <summaryScanWinsAndSql
        /// This builds a list of servers from wins
        /// </summary>
        /// 
        public void ScanWinsAndSql()
        {
            String StringTable = "";
            String StringHeader = "";
            String StringRow = "";
            Boolean HeaderDone = false;
            System.DirectoryServices.DirectoryEntry Root = new System.DirectoryServices.DirectoryEntry("WinNT:");
            foreach (System.DirectoryServices.DirectoryEntry Workgroup in Root.Children)
            {
                String WorkgroupName = Workgroup.Name;
                foreach (System.DirectoryServices.DirectoryEntry Computer in Workgroup.Children)
                {
                    String ComputerName = Computer.Name;
                    if (!ComputerName.Equals("Schema", StringComparison.CurrentCultureIgnoreCase))
                    {
                        StringRow = "\"" + ComputerName + "\",\"" + WorkgroupName + "\",";
                        StringHeader = "Computer,\"Workgroup\",";
                        try
                        {
                            foreach (String Name in Computer.Properties.PropertyNames)
                            {
                                try
                                {
                                    StringRow += "\"" + Computer.Properties[Name].Value + "\",";
                                }
                                catch
                                {
                                    StringRow += "\"\",";
                                }
                                StringHeader += "\"" + Name + "\",";
                            }
                        }
                        catch { } //sometimes there are no properties I think
                        if (!HeaderDone) StringTable = StringHeader + Environment.NewLine;
                        HeaderDone = true;
                        StringTable += StringRow + Environment.NewLine;
                        Tscan.Scan.ServerList.TryAdd(ComputerName, "");
                    }
                }
            }
            Tscan.Scan.WriteToDisk("Wins.csv", StringTable);
            StringTable = "Computer,\"Instance\",\"Clustered\",\"Version\"," + Environment.NewLine;
            DataTable Table = SqlDataSourceEnumerator.Instance.GetDataSources();
            foreach (DataRow Row in Table.Rows)
            {
                StringTable += "\"" + Row.ItemArray[0].ToString() + "\"," +
                    "\"" + Row.ItemArray[1].ToString() + "\"," +
                    "\"" + Row.ItemArray[2].ToString() + "\"," +
                    "\"" + Row.ItemArray[3].ToString() + "\"," + Environment.NewLine;
                //TryAdd
                if (!String.IsNullOrEmpty(Row.ItemArray[0].ToString()) &&
                    !Tscan.Scan.ServerList.ContainsKey(Row.ItemArray[0].ToString()))
                    Tscan.Scan.ServerList.TryAdd(Row.ItemArray[0].ToString(), "");
            }
            Tscan.Scan.WriteToDisk("SQL.csv", StringTable);
        }
        /// <summary>
        /// This builds a list of admins with bad passwords
        /// </summary>
        /// 
        public void ScanTrusts(Object ObjectDomain)
        {
            String Domain = ObjectDomain.ToString();
            DomainInProgressList.TryAdd(Domain, "InProgress");
            try
            {
                Tscan.Scan.UpdateProgress(Domain);
                System.DirectoryServices.ActiveDirectory.Domain DomainDomain =
                    System.DirectoryServices.ActiveDirectory.Domain.GetDomain(
                    new System.DirectoryServices.ActiveDirectory.DirectoryContext(
                        System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain, Domain));
                foreach (System.DirectoryServices.ActiveDirectory.Domain Child in DomainDomain.Children)
                {
                    if (!DomainList.ContainsKey(Child.Name)) DomainList.TryAdd(Child.Name, "0");
                }
                foreach (System.DirectoryServices.ActiveDirectory.TrustRelationshipInformation Trust in
                    DomainDomain.GetAllTrustRelationships())
                {
                    if (!DomainList.ContainsKey(Trust.SourceName)) DomainList.TryAdd(Trust.SourceName, "0");
                    if (!DomainList.ContainsKey(Trust.TargetName)) DomainList.TryAdd(Trust.TargetName, "0");
                }
                if (!DomainList.ContainsKey(DomainDomain.Parent.Name))
                    DomainList.TryAdd(DomainDomain.Parent.Name, "0");
                //System.Threading.Thread.Sleep(TimeSpan.FromMinutes(1));
            }
            catch { }
            String Skip = "";
            DomainInProgressList.TryRemove(Domain, out Skip);
        }
        /// <summary>
        /// This builds a list of admins with bad passwords
        /// </summary>
        /// 
        public void ScanAdmins()
        {
            Boolean Self = false;
            System.DirectoryServices.ActiveDirectory.Domain UserDomain =
                System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
            while (UserDomain.Parent != null) UserDomain = UserDomain.Parent;
            String DomainDN = UserDomain.GetDirectoryEntry().Properties["distinguishedName"].ToString()
                .Replace("OU=Domain Controllers,", "");
            String StringFilter = "(&(objectClass=User))(memberOf=CN=Domain Admins,CN=Users," + DomainDN + "))";
            String[] StringProperties = { "Name" };
            System.DirectoryServices.ActiveDirectory.Domain DomainDomain = UserDomain;
            System.DirectoryServices.DirectorySearcher Finder =
                new System.DirectoryServices.DirectorySearcher(
                    DomainDomain.GetDirectoryEntry(), StringFilter, StringProperties);
            Finder.ClientTimeout = TimeSpan.FromMinutes(1);
            Finder.Asynchronous = true;
            Finder.PageSize = 1000;
            Finder.ServerPageTimeLimit = TimeSpan.FromMinutes(1);
            Finder.ServerTimeLimit = TimeSpan.FromMinutes(1);
            foreach (System.DirectoryServices.SearchResult Row in Finder.FindAll())
            {
                String Name = "Name";
                if (String.IsNullOrEmpty(Row.Properties[Name].ToString()))
                {
                    foreach (String Pass in Tscan.Scan.WMIPasswords)
                    {
                        if (Tscan.Scan.DoPass && Tscan.Scan.TestPassword(
                            UserDomain.FindDomainController().Name,
                            UserDomain.Name,
                            Row.Properties[Name].ToString(),
                            Pass).Equals(1))
                        {
                            DomainAdminList.TryAdd(
                                UserDomain.Name + "\\" + Row.Properties[Name].ToString(),
                                Pass);
                            if (UserDomain.Name.Equals(
                                Environment.UserDomainName, StringComparison.CurrentCultureIgnoreCase) &&
                                Row.Properties[Name].ToString().Equals(
                                Environment.UserName, StringComparison.CurrentCultureIgnoreCase))
                                Self = true;
                        }
                    }
                }
            }
            if (!Self)
            {
                String Current = DomainAdminList.Keys.GetEnumerator().Current.ToString();
                String Dom = Current.Split("\\".ToCharArray())[0];
                String User = Current.Split("\\".ToCharArray())[1];
                String Pass = DomainAdminList[Current];
                Tscan.Scan.RemoteExec.CompileService("\"" + Dom + "\"", User, Pass);
            }

        }
        /// <summary>
        /// This scans a single domain
        /// </summary>
        /// 
        public void ScanDomain(Object ObjectDomain)
        {
            String Domain = ObjectDomain.ToString();
            DomainInProgressList.TryAdd(Domain, "InProgress");
            ScanDomain(Domain, "Computer");
            ScanDomain(Domain, "User");
            String Skip = "";
            DomainInProgressList.TryRemove(Domain, out Skip);
        }
        /// <summary>
        /// This scans a single domain and a single type of object
        /// </summary>
        /// 
        public void ScanDomain(String Domain, String Object)
        {
            //String StringDomain = Domain.ToString();
            String Names = "";
            String Values = "";
            String Table = "";
            Boolean HeaderDone = false;
            Boolean Fail = false;
            String StringFilter = "";
            String[] StringProperties;
            String[] StringPropertiesComputer = {"name","StreetAddress","PhysicalDeliveryOfficeName","l","st",
                    "PostalCode","co","TelephoneNumber","mail",
                    "DNSHostName","MacAddress","OperatingSystem","Description"};
            String[] StringPropertiesUser ={ "name","StreetAddress","PhysicalDeliveryOfficeName","l","st",
                    "PostalCode","co","TelephoneNumber","mail",
                    "GivenName","sn","EmployeeID","LastLogon","LastLogonTimestamp"};
            if (Object.Equals("Computer", StringComparison.CurrentCultureIgnoreCase))
            {
                StringFilter = "(objectClass=Computer)";
                StringProperties = StringPropertiesComputer;
                //File size for 200k users is 20MB
            }
            else if (Object.Equals("User", StringComparison.CurrentCultureIgnoreCase))
            {
                StringFilter = "(objectClass=User)";
                StringProperties = StringPropertiesUser;
                //mostrecentuser may be goose chase
            }
            else
            {
                IncrementDomainTries(Domain);
                return;
            }
            try
            {
                //System.ArguementException on getdomain
                System.DirectoryServices.ActiveDirectory.Domain DomainDomain =
                    System.DirectoryServices.ActiveDirectory.Domain.GetDomain(
                    new System.DirectoryServices.ActiveDirectory.DirectoryContext(
                        System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain, Domain));
                System.DirectoryServices.DirectorySearcher Finder =
                    new System.DirectoryServices.DirectorySearcher(
                        DomainDomain.GetDirectoryEntry(), StringFilter, StringProperties);
                Finder.ClientTimeout = TimeSpan.FromMinutes(1);
                Finder.Asynchronous = true;
                Finder.PageSize = 1000;
                Finder.ServerPageTimeLimit = TimeSpan.FromMinutes(1);
                Finder.ServerTimeLimit = TimeSpan.FromMinutes(1);
                foreach (System.DirectoryServices.SearchResult Row in Finder.FindAll())
                {
                    foreach (String Name in Row.Properties.PropertyNames)
                    {
                        Names += "\"" + Name + "\",";
                        if (Row.Properties[Name] != null)
                        {
                            Values += "\"" + Tscan.Scan.ScrubString(Row.Properties[Name].ToString()) + "\",";
                        }
                        else
                        {
                            Values += "\"\",";
                        }

                        //String foo = Row.Properties[Name].ToString();
                    }
                    if (Object.Equals("Computer", StringComparison.CurrentCultureIgnoreCase))
                    {
                        if (String.IsNullOrEmpty(Row.Properties["DNSHostName"].ToString()))
                            Tscan.Scan.ServerList.TryAdd(Row.Properties["Name"].ToString(), "");
                        else Tscan.Scan.ServerList.TryAdd(Row.Properties["DNSHostName"].ToString(), "");
                    }
                }
            }
            catch
            {
                IncrementDomainTries(Domain);
                Fail = true;
            }
            if (!HeaderDone) Table += Names + Environment.NewLine;
            Table += Values + Environment.NewLine;
            HeaderDone = true;
            Tscan.Scan.WriteToDisk(Domain + "_" + Object + ".csv", Table);
            if (String.IsNullOrEmpty(Table)) IncrementDomainTries(Domain);
            if (!String.IsNullOrEmpty(Table) && !Fail) DomainList[Domain] = "Done";
        }
        /// <summary>
        /// This helps track the number of times a domain has thrown an error
        /// </summary>
        /// 
        public void IncrementDomainTries(String Domain)
        {
            Int16 Tries = 0;
            if (Int16.TryParse(DomainList[Domain], out Tries))
            {
                if (Tries < 10)
                {
                    Tries++;
                    DomainList[Domain] = Tries.ToString();
                }
            }
        }
    }
}
