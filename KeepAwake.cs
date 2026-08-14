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

			try
			{
				Application.Run(new TrayApplicationContext());
			}
			catch (Exception ex)
			{
				Environment.ExitCode = 1;
				MessageBox.Show("Keep Awake failed to start: " + ex.Message, "Keep Awake", MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}
	}

	public class TrayApplicationContext : ApplicationContext
	{
		private NotifyIcon trayIcon;
		private ContextMenuStrip menu;
		private Icon iconOn;
		private Icon iconOff;
		private bool preventSuspendEnabled;
		private bool cleanedUp;

		private IntPtr powerRequestHandle = IntPtr.Zero;
		private Guid activeSchemeGuid;
		private int savedTimeout;

		public TrayApplicationContext()
		{
			try
			{
				LoadIcons();

				menu = new ContextMenuStrip();
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
			catch
			{
				// Release the power request handle and UI resources if startup fails
				// partway through; Main() reports the error to the user.
				Cleanup();
				throw;
			}
		}

		// Loads the two tray icons that ship embedded inside this assembly as resources.
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
			try
			{
				if (preventSuspendEnabled)
					DisablePreventSuspend();
				else
					EnablePreventSuspend();
			}
			catch (Exception ex)
			{
				MessageBox.Show("Keep Awake could not change the sleep state: " + ex.Message, "Keep Awake", MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}

		private void OnExit(object sender, EventArgs e)
		{
			Cleanup();
			ExitThread();
		}

		private void SystemEvents_SessionEnding(object sender, SessionEndingEventArgs e)
		{
			Cleanup();
		}

		private void CurrentDomain_ProcessExit(object sender, EventArgs e)
		{
			Cleanup();
		}

		private void Cleanup()
		{
			if (cleanedUp)
				return;
			cleanedUp = true;

			// Restore the saved power timeout first (best-effort).
			try
			{
				if (preventSuspendEnabled)
					DisablePreventSuspend();
			}
			catch
			{
				// best-effort cleanup on shutdown/exit
			}

			// Always close the request handle, even if the restore above threw.
			if (powerRequestHandle != IntPtr.Zero)
			{
				CloseHandle(powerRequestHandle);
				powerRequestHandle = IntPtr.Zero;
			}

			DisposeResources();
		}

		private void DisposeResources()
		{
			try
			{
				SystemEvents.SessionEnding -= SystemEvents_SessionEnding;
			}
			catch
			{
				// best-effort
			}

			try
			{
				if (trayIcon != null)
				{
					trayIcon.Visible = false;
					trayIcon.Dispose();
					trayIcon = null;
				}

				if (menu != null)
				{
					menu.Dispose();
					menu = null;
				}

				if (iconOn != null)
				{
					iconOn.Dispose();
					iconOn = null;
				}

				if (iconOff != null)
				{
					iconOff.Dispose();
					iconOff = null;
				}
			}
			catch
			{
				// best-effort resource cleanup
			}
		}

		private void FatalError(string message)
		{
			Cleanup();
			MessageBox.Show(message, "Keep Awake", MessageBoxButtons.OK, MessageBoxIcon.Error);
			Environment.Exit(1);
		}

		#region Power management

		// Reads the active power scheme and checks whether the Modern Standby /
		// "execution required" idle-resiliency setting exists on this machine, then bails
		// out gracefully with a message box if it doesn't (older systems / some VMs don't
		// expose it).
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
				FatalError("Connected Standby / Modern Standby does not appear to be supported on this system. Keep Awake cannot continue.");
			}

			POWER_REQUEST_CONTEXT context = new POWER_REQUEST_CONTEXT();
			context.Version = POWER_REQUEST_CONTEXT_VERSION;
			context.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
			context.SimpleReasonString = "Keep Awake - prevent system suspend";
			powerRequestHandle = PowerCreateRequest(ref context);
			if (powerRequestHandle == IntPtr.Zero)
				ThrowLastWin32Error();
		}

		// This pair of methods (EnablePreventSuspend/DisablePreventSuspend below) is the
		// entire point of the app: they write the "execution required" idle-resiliency
		// timeout to -1 (never suspend) and register a PowerRequestExecutionRequired
		// request, then reassert the active scheme so Windows picks the change up
		// immediately.
		private void EnablePreventSuspend()
		{
			bool timeoutWritten = false;
			try
			{
				uint hr = PowerWriteDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, NEVER_SUSPEND);
				if (hr != 0)
					Marshal.ThrowExceptionForHR((int)hr);
				timeoutWritten = true;

				if (!PowerSetRequest(powerRequestHandle, PowerRequestType.PowerRequestExecutionRequired))
					ThrowLastWin32Error();

				// Mark as enabled before re-applying so that Cleanup() restores the
				// saved timeout if ReapplyActiveScheme() fails fatally below.
				preventSuspendEnabled = true;

				ReapplyActiveScheme();
			}
			catch
			{
				// A partial failure must not leave the "never suspend" timeout in
				// place: restore the saved value before propagating the error.
				if (timeoutWritten)
				{
					preventSuspendEnabled = false;
					try
					{
						PowerWriteDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, savedTimeout);
						TryReapplyActiveScheme();
					}
					catch
					{
						// best-effort rollback; the original error is still reported
					}
				}
				throw;
			}

			UpdateTrayState();
		}

		private void DisablePreventSuspend()
		{
			if (!PowerClearRequest(powerRequestHandle, PowerRequestType.PowerRequestExecutionRequired))
				ThrowLastWin32Error();

			// The request is what actually keeps the system awake, so reflect that it
			// is now off before attempting the timeout restore, which can still fail
			// and otherwise leave the tray icon reporting "on".
			preventSuspendEnabled = false;

			try
			{
				uint hr = PowerWriteDCValueIndex(IntPtr.Zero, activeSchemeGuid, GUID_IDLE_RESILIENCY_SUBGROUP, GUID_EXECUTION_REQUIRED_REQUEST_TIMEOUT, savedTimeout);
				if (hr != 0)
					Marshal.ThrowExceptionForHR((int)hr);

				TryReapplyActiveScheme();
			}
			finally
			{
				// Keep the tray icon in sync with the new state even if the
				// timeout restore threw.
				UpdateTrayState();
			}
		}

		private void ReapplyActiveScheme()
		{
			if (TryReapplyActiveScheme())
				return;

			// If the active scheme can't be read, the system's sleep settings may be
			// left modified and we can't be sure of the state - tell the user, clean
			// up, and exit.
			FatalError("Keep Awake could not re-apply the active power scheme. Keep Awake will now exit.");
		}

		private bool TryReapplyActiveScheme()
		{
			IntPtr curScheme;
			if (PowerGetActiveScheme(IntPtr.Zero, out curScheme) != 0)
				return false;

			PowerSetActiveScheme(IntPtr.Zero, curScheme);
			LocalFree(curScheme);
			return true;
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
		const int NEVER_SUSPEND = -1; // "execution required" requests never time out

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
