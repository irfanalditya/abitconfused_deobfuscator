using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.Unknown {
	public static class SimpleDeobfscators {
		public static void Deobfuscate(MethodDef method) {
			SimpleDeobfuscatorFlags flags = 0;
			bool force = (flags & SimpleDeobfuscatorFlags.Force) != 0;
			if (method == null || !force) {
				return;
			}
			Deobfuscate(method, delegate (Blocks blocks) {
				bool disableNewCfCode = (flags & SimpleDeobfuscatorFlags.DisableConstantsFolderExtraInstrs) != 0;
				var cflowDeobfuscator = new BlocksCflowDeobfuscator();
				cflowDeobfuscator.Initialize(blocks);
				cflowDeobfuscator.Deobfuscate();
			});
		}
		private static void Deobfuscate(MethodDef method, Action<Blocks> handler) {
			if (!method.HasBody || !method.Body.HasInstructions)
				return;
			var blocks = new Blocks(method);
			handler(blocks);
			blocks.RepartitionBlocks();
			blocks.GetCode(out var allInstructions, out var allExceptionHandlers);
			DotNetUtils.RestoreBody(method, allInstructions, allExceptionHandlers);
		}
		private static BlocksCflowDeobfuscator _blocksCflowDeob = new();

		private static readonly Dictionary<MethodDef, SimpleDeobFlags> DeobfuscatorFlags = new();

		[Flags] private enum SimpleDeobFlags { HasDeobfuscated = 1 }

		[Flags] public enum SimpleDeobfuscatorFlags : uint { Force = 1U, DisableConstantsFolderExtraInstrs = 2U }
	}
}
