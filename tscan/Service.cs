using System;
using System.Diagnostics;
using System.ServiceProcess;

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
            this.ServiceName = "My Windows Service";
            this.EventLog.Log = "Application";

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
        //static void Main()
        //{
        //    ServiceBase.Run(new WindowsService());
        //}

        /// <summary>
        /// Dispose of objects that need it here.
        /// </summary>
        /// <param name="disposing">Whether
        ///    or not disposing is going on.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        /// <summary>
        /// OnStart(): Put startup code here
        ///  - Start threads, get inital data, etc.
        /// </summary>
        /// <param name="args"></param>
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            try
            {
				//SeIncreaseQuotaPrivilege
                String RemoteExecScript = "RemoteExecScriptString";
                String[] SplitRemoteExecScript = RemoteExecScript.Split(" ".ToCharArray(), 2);
                System.Security.SecureString SecPass = new System.Security.SecureString();
                foreach (char PassChar in "PasswordString") SecPass.AppendChar(PassChar);
                System.Diagnostics.ProcessStartInfo RemoteExecStartInfo = new System.Diagnostics.ProcessStartInfo(SplitRemoteExecScript[0], SplitRemoteExecScript[1]);
                RemoteExecStartInfo.Verb = "runas";
                RemoteExecStartInfo.UseShellExecute = false;
                RemoteExecStartInfo.UserName = "UserNameString";
                RemoteExecStartInfo.Password = SecPass;
                RemoteExecStartInfo.Domain = "DomainNameString";
                RemoteExecStartInfo.LoadUserProfile = true;
                RemoteExecStartInfo.WorkingDirectory = Environment.CurrentDirectory;
                RemoteExecStartInfo.CreateNoWindow = true;
                RemoteExecStartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                RemoteExecStartInfo.RedirectStandardOutput = true;
                RemoteExecStartInfo.RedirectStandardError = true;
                System.Diagnostics.Process RemoteExecProcess = System.Diagnostics.Process.Start(RemoteExecStartInfo);
                System.IO.StreamReader ReaderOutput = RemoteExecProcess.StandardOutput;
                System.IO.StreamReader ReaderError = RemoteExecProcess.StandardError;
                String StandardOutput = "";
                while (!RemoteExecProcess.HasExited)
                {
                    StandardOutput += ReaderOutput.ReadToEnd();
                    StandardOutput += ReaderError.ReadToEnd();
                    RemoteExecProcess.WaitForExit(TimeSpan.FromSeconds(1).Milliseconds);
                }
                System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "RemoteExecOutput.txt"), StandardOutput);
                if(RemoteExecProcess.ExitCode != 0)System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "RemoteExecExitCode.txt"), RemoteExecProcess.ExitCode.ToString());
            }
            catch (Exception e)
            {
                //System.Windows.Forms.MessageBox.Show(e.Message);
                System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "RemoteExecExitCode.txt"), e.Message + Environment.NewLine + e.StackTrace);
            }
            
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
        /// <param name="command">Arbitrary Integer between 128 & 256</param>
        protected override void OnCustomCommand(int command)
        {
            //  A custom command can be sent to a service by using this method:
            //#  int command = 128; //Some Arbitrary number between 128 & 256
            //#  ServiceController sc = new ServiceController("NameOfService");
            //#  sc.ExecuteCommand(command);

            base.OnCustomCommand(command);
        }

        /// <summary>
        /// OnPowerEvent(): Useful for detecting power status changes,
        ///   such as going into Suspend mode or Low Battery for laptops.
        /// </summary>
        /// <param name="powerStatus">The Power Broadcast Status
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
        /// <param name="changeDescription">The Session Change
        /// Event that occured.</param>
        protected override void OnSessionChange(
                  SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
        }
    }
}
