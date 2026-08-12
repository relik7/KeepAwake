using System;
using System.ComponentModel;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

// General assembly info.
[assembly: AssemblyTitle("Keep Awake")]
[assembly: AssemblyDescription("Tray utility that prevents the system from entering Modern Standby / sleep.")]
[assembly: AssemblyConfiguration("Release")]
[assembly: AssemblyCompany("github.com/relik7")]
[assembly: AssemblyProduct("Keep Awake")]
[assembly: AssemblyCopyright("Copyright © 2026")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
 
[assembly: ComVisible(false)]
[assembly: Guid("0e910fec-87a2-4f90-8e31-5c3d2133df8e")]

[assembly: AssemblyVersion("1.0.1.0")]
[assembly: AssemblyFileVersion("1.0.1.0")]

namespace KeepAwake
{
	static class Program
	{
		[STAThread]
		static void Main()
		{
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.Run(new TrayApplicationContext());
		}
	}

	public class TrayApplicationContext : ApplicationContext
	{
		private NotifyIcon trayIcon;
		private Icon iconOn;
		private Icon iconOff;
		private bool preventSuspendEnabled;
		private bool cleanedUp;

		private IntPtr powerRequestHandle = IntPtr.Zero;
		private Guid activeSchemeGuid;
		private int savedTimeout;

		public TrayApplicationContext()
		{
			LoadIcons();

			ContextMenuStrip menu = new ContextMenuStrip();
			menu.Items.Add("Exit", null, OnExit);

			trayIcon = new NotifyIcon();
			trayIcon.Icon = iconOff;
			trayIcon.Text = "Keep Awake";
			trayIcon.ContextMenuStrip = menu;
			trayIcon.MouseUp += TrayIcon_MouseUp;
			trayIcon.Visible = true;

			SystemEvents.SessionEnding += SystemEvents_SessionEnding;
			AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;

			InitializePower();

			// Default to preventing suspend on startup
			EnablePreventSuspend();
		}

		private void LoadIcons()
		{
			Assembly asm = Assembly.GetExecutingAssembly();
			using (System.IO.Stream stream = asm.GetManifestResourceStream("KeepAwake.ico"))
			{
				iconOn = new Icon(stream, 16, 16);
			}
			using (System.IO.Stream stream = asm.GetManifestResourceStream("KeepAwake_off.ico"))
			{
				iconOff = new Icon(stream, 16, 16);
			}
		}

		private void TrayIcon_MouseUp(object sender, MouseEventArgs e)
		{
			if (e.Button == MouseButtons.Left)
			{
				Toggle();
			}
		}

		private void Toggle()
		{
			if (preventSuspendEnabled)
				DisablePreventSuspend();
			else
				EnablePreventSuspend();
		}

		private void OnExit(object sender, EventArgs e)
		{
			trayIcon.Visible = false;
			Cleanup();
			ExitThread();
		}

		private void SystemEvents_SessionEnding(object sender, SessionEndingEventArgs e)
		{
			trayIcon.Visible = false;
			Cleanup();
		}

		private void CurrentDomain_ProcessExit(object sender, EventArgs e)
		{
			if (trayIcon != null)
				trayIcon.Visible = false;
			Cleanup();
		}

		private void Cleanup()
		{
			if (cleanedUp)
				return;
			cleanedUp = true;

			try
			{
				if (preventSuspendEnabled)
					DisablePreventSuspend();

				if (powerRequestHandle != IntPtr.Zero)
				{
					CloseHandle(powerRequestHandle);
					powerRequestHandle = IntPtr.Zero;
				}
			}
			catch
			{
				// best-effort cleanup on shutdown/exit
			}
		}

		#region Power management

		private void InitializePower()
		{
			IntPtr pActiveSchemeGuid;
			uint hr = PowerGetActiveScheme(IntPtr.Zero, out pActiveSchemeGuid);
			if (hr != 0)
				Marshal.ThrowExceptionForHR((int)hr);
			activeSchemeGuid = (Guid)Marshal.PtrToStructure(pActiveSchemeGuid, typeof(Guid));
			LocalFree(pActiveSchemeGuid);

			uint readHr = PowerReadDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, out savedTimeout);
			if (readHr != 0)
			{
				MessageBox.Show("Connected Standby / Modern Standby does not appear to be supported on this system. Keep Awake cannot continue.", "Keep Awake", MessageBoxButtons.OK, MessageBoxIcon.Error);
				Environment.Exit(1);
			}

			POWER_REQUEST_CONTEXT context = new POWER_REQUEST_CONTEXT();
			context.Version = POWER_REQUEST_CONTEXT_VERSION;
			context.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
			context.SimpleReasonString = "Keep Awake - prevent system suspend";
			powerRequestHandle = PowerCreateRequest(ref context);
			if (powerRequestHandle == IntPtr.Zero)
				ThrowLastWin32Error();
		}

		private void EnablePreventSuspend()
		{
			uint hr = PowerWriteDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, -1);
			if (hr != 0)
				Marshal.ThrowExceptionForHR((int)hr);

			if (!PowerSetRequest(powerRequestHandle, PowerRequestType.PowerRequestExecutionRequired))
				ThrowLastWin32Error();

			ReapplyActiveScheme();

			preventSuspendEnabled = true;
			UpdateTrayState();
		}

		private void DisablePreventSuspend()
		{
			PowerClearRequest(powerRequestHandle, PowerRequestType.PowerRequestExecutionRequired);

			uint hr = PowerWriteDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, savedTimeout);
			if (hr != 0)
				Marshal.ThrowExceptionForHR((int)hr);

			ReapplyActiveScheme();

			preventSuspendEnabled = false;
			UpdateTrayState();
		}

		private void ReapplyActiveScheme()
		{
			IntPtr curScheme;
			PowerGetActiveScheme(IntPtr.Zero, out curScheme);
			PowerSetActiveScheme(IntPtr.Zero, curScheme);
			LocalFree(curScheme);
		}

		private void UpdateTrayState()
		{
			if (trayIcon == null)
				return;

			if (preventSuspendEnabled)
			{
				trayIcon.Icon = iconOn;
				trayIcon.Text = "Keep Awake";
			}
			else
			{
				trayIcon.Icon = iconOff;
				trayIcon.Text = "Sleep Allowed";
			}
		}

		#endregion

		#region Win32 / Power API interop

		static void ThrowLastWin32Error()
		{
			throw new Win32Exception(Marshal.GetLastWin32Error());
		}

		enum PowerRequestType
		{
			PowerRequestDisplayRequired = 0,
			PowerRequestSystemRequired = 1,
			PowerRequestAwayModeRequired = 2,
			PowerRequestExecutionRequired = 3,
			PowerRequestMaximum
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		struct POWER_REQUEST_CONTEXT
		{
			public UInt32 Version;
			public UInt32 Flags;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string SimpleReasonString;
		}

		const int POWER_REQUEST_CONTEXT_VERSION = 0;
		const int POWER_REQUEST_CONTEXT_SIMPLE_STRING = 0x1;

		static readonly Guid GUID_IDLE_RESILIENCY_SUBGROUP = new Guid(0x2e601130, 0x5351, 0x4d9d, 0x8e, 0x4, 0x25, 0x29, 0x66, 0xba, 0xd0, 0x54);
		static readonly Guid GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT = new Guid(0x3166bc41, 0x7e98, 0x4e03, 0xb3, 0x4e, 0xec, 0xf, 0x5f, 0x2b, 0x21, 0x8e);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr PowerCreateRequest(ref POWER_REQUEST_CONTEXT Context);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool PowerSetRequest(IntPtr PowerRequestHandle, PowerRequestType RequestType);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool PowerClearRequest(IntPtr PowerRequestHandle, PowerRequestType RequestType);
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern bool CloseHandle(IntPtr hObject);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr LocalFree(IntPtr hMem);
		[DllImport("PowrProf.dll", CharSet = CharSet.Unicode)]
		static extern UInt32 PowerWriteDCValueIndex(IntPtr RootPowerKey, [MarshalAs(UnmanagedType.LPStruct)] Guid SchemeGuid, [MarshalAs(UnmanagedType.LPStruct)] Guid SubGroupOfPowerSettingsGuid, [MarshalAs(UnmanagedType.LPStruct)] Guid PowerSettingGuid, int AcValueIndex);
		[DllImport("PowrProf.dll", CharSet = CharSet.Unicode)]
		static extern UInt32 PowerReadDCValueIndex(IntPtr RootPowerKey, [MarshalAs(UnmanagedType.LPStruct)] Guid SchemeGuid, [MarshalAs(UnmanagedType.LPStruct)] Guid SubGroupOfPowerSettingsGuid, [MarshalAs(UnmanagedType.LPStruct)] Guid PowerSettingGuid, out int AcValueIndex);
		[DllImport("PowrProf.dll", CharSet = CharSet.Unicode)]
		static extern UInt32 PowerGetActiveScheme(IntPtr UserPowerKey, out IntPtr ActivePolicyGuid);
		[DllImport("PowrProf.dll", CharSet = CharSet.Unicode)]
		static extern UInt32 PowerSetActiveScheme(IntPtr UserPowerKey, IntPtr ActivePolicyGuid);

		#endregion
	}
}
