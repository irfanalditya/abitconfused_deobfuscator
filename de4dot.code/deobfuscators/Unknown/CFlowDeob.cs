using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using de4dot.blocks;
using System.IO;

namespace de4dot.code.deobfuscators.Unknown {
	public class CFlowDeob {
		private ModuleDefMD module;
		private Dictionary<uint, int> intfields = new Dictionary<uint, int>();
		public CFlowDeob(ModuleDefMD module) {
			this.module = module;
		}
		public void Deob() {
			byte[] data = File.ReadAllBytes(@"E:\CTF\drweb2024\3\stringresource.dat");
			intfields = GetFieldsDictionary();
			if (intfields.Count == 0)
				return;

			List<MethodDef> methods = Utils.GetAllMethodDefs(module);
			foreach (MethodDef method in methods) {
				if (method.MDToken.Raw == 0x0600000F)
					continue;
				if (!method.HasBody || !method.Body.HasInstructions)
					continue;
				if (!IsCflow(method))
					continue;

				int localIndex1 = method.Body.Instructions[1].GetLocal(method.Body.Variables).Index;
				int localIndex2 = localIndex1 - 1;

				var blocks = new Blocks(method);

				// create raw switch block
				Block switchBlock = new Block();
				blocks.MethodBlocks.Add(switchBlock);
				var allBlocks = Utils.GetAllBlocks(blocks.MethodBlocks.BaseBlocks);
				allBlocks[0].SetNewFallThrough(switchBlock);
				switchBlock.SetNewFallThrough(allBlocks[0]);
				//======================================================

				Dictionary<int, Block> blocks1 = GetBlock(allBlocks, method.Body.Variables, localIndex1);
				if (blocks1.Count == 0)
					continue;

				Dictionary<int, Block> blocks2 = GetBlock(allBlocks, method.Body.Variables, localIndex2);
				if (blocks2.Count == 0)
					continue;

				ResolveFlow(blocks1, blocks2, switchBlock, method.Body.Variables, localIndex1, localIndex2);

				// resolve switch block
				IList<Block> targets = new List<Block>();
				for (int i = 0; i < blocks1.Count; i++) {
					if (blocks1.TryGetValue(i, out var block)) {
						targets.Add(block);
					}
				}

				if (blocks1.Count != targets.Count) {
					Console.WriteLine("ERROR: blocks1.Count != targets.Count");
					return;
				}

				Instr ldloc_instr = new Instr(Instruction.Create(OpCodes.Ldloc, method.Body.Variables[localIndex1]));
				IList<Instruction> targets_instr = new List<Instruction>();
				foreach (var target in targets) {
					targets_instr.Add(target.FirstInstr.Instruction);
				}

				Instr switch_instr = new Instr(Instruction.Create(OpCodes.Switch, targets_instr));

				switchBlock.Add(ldloc_instr);
				switchBlock.Add(switch_instr);

				switchBlock.Targets = new List<Block>();
				foreach (var target in targets) {
					switchBlock.Targets.Add(target);
					target.Sources.Add(switchBlock);
				}
				//======================================================

				// clear num1 with NULL sources
				foreach (var b in allBlocks) {
					if (b.Sources.Count != 0)
						continue;
					for (int i = 0; i < b.Instructions.Count - 1; i++) {
						if (b.Instructions[i].OpCode != OpCodes.Ldsfld)
							continue;
						if (!b.Instructions[i + 1].IsStloc())
							continue;
						if (b.Instructions[i + 1].Instruction.GetLocal(method.Body.Variables).Index != localIndex1)
							continue;
						b.Instructions.Clear();
						b.RemoveGuaranteedDeadBlock();
					}
				}
				//========================================================

				blocks.GetCode(out var allInstructions, out var allExceptionHandlers);
				DotNetUtils.RestoreBody(method, allInstructions, allExceptionHandlers);

				var blocksA = new Blocks(method);
				var allBlocksA = Utils.GetAllBlocks(blocksA.MethodBlocks.BaseBlocks);
				ResolveFields(allBlocksA);

				blocksA.GetCode(out var allInstructionsA, out var allExceptionHandlersA);
				DotNetUtils.RestoreBody(method, allInstructionsA, allExceptionHandlersA);

				SimpleDeobfscators.Deobfuscate(method);

				var blocksB = new Blocks(method);
				var allBlocksB = Utils.GetAllBlocks(blocksB.MethodBlocks.BaseBlocks);
				decryptStr(allBlocksB, method, data);

				blocksB.GetCode(out var allInstructionsB, out var allExceptionHandlersB);
				DotNetUtils.RestoreBody(method, allInstructionsB, allExceptionHandlersB);
			}
		}
		private void decryptStr(List<Block> blocks, MethodDef method, byte[] data) {
			try {
				uint decrypterToken = 0x06000001;
				foreach (var block in blocks) {
					if (block.Instructions.Count == 0)
						continue;

					var instructions = block.Instructions;
					int i = 0;
					while (i < instructions.Count - 3) {
						if (instructions[i].OpCode == OpCodes.Ldstr &&
							instructions[i + 1].IsLdcI4() &&
							instructions[i + 2].IsLdcI4() &&
							instructions[i + 3].OpCode == OpCodes.Call) {
							MethodDef calledMethod = instructions[i + 3].Operand as MethodDef;
							if (calledMethod.MDToken.Raw != decrypterToken) {
								i++;
								continue;
							}

							int a1 = instructions[i + 1].GetLdcI4Value();
							int a2 = instructions[i + 2].GetLdcI4Value();
							string decryptedString = doDecryptString(data, a1, a2, method.Name);
							instructions[i].Operand = decryptedString;
							instructions.RemoveAt(i + 1);
							instructions.RemoveAt(i + 1);
							instructions.RemoveAt(i + 1);
						}
						i++;
					}
				}
			}
			catch (Exception e) {
				Console.WriteLine(e.Message);
			}
		}
		private string doDecryptString(byte[] data, int a1, int a2, string methodName) {
			byte[] bytesName = Encoding.Default.GetBytes(methodName);
			int num = -0x7EE3623B;
			for(int i = 0; i < bytesName.Length; i++) {
				num = (num ^ (int)bytesName[i]) * 0x1000193;
			}
			num += num << 0xD;
			num ^= num >> 7;
			List<byte> list = new List<byte>();
			a1 += num;
			for (int i = 0; i <a2; i++) {
				list.Add(data[a1 + i]);
			}
			return Encoding.UTF8.GetString(list.ToArray());
		}
		private void ResolveFlow(Dictionary<int, Block> blocks1, Dictionary<int, Block> blocks2, Block switchblock, LocalList locals, int local1index, int local2index) {
			for (int i = 0; i < blocks1.Count; i++) {
				if (blocks1.TryGetValue(i, out Block target)) {
					Block fall = target.FallThrough;
					if (fall.Instructions.Count == 1 && fall.FirstInstr.IsNop()) {
						fall = target.FallThrough.FallThrough;
					}
					int index1 = GetStLocIndex(fall.Instructions, locals, local1index);
					int index2 = GetStLocIndex(fall.Instructions, locals, local2index);

					if (index2 != -1 && index1 != -1) {
						int value1 = GetIntFromFields(fall.Instructions[index1 - 1].Instruction);
						int value2 = GetIntFromFields(fall.Instructions[index2 - 1].Instruction);
						if (blocks1.TryGetValue(value1, out var block1) && blocks2.TryGetValue(value2, out var block2)) {
							int index3 = GetStLocIndex(block2.FallThrough.Instructions, locals, local1index);

							block1.Instructions.Clear();
							block1.Instructions.Add(new Instr(Instruction.Create(OpCodes.Ldsfld, block2.FallThrough.Instructions[index3 - 1].Operand as FieldDef)));
							block1.Instructions.Add(new Instr(Instruction.Create(OpCodes.Stloc, block2.FallThrough.Instructions[index3].Instruction.GetLocal(locals))));
							block1.DisconnectFromFallThroughAndTargets();
							block1.SetNewFallThrough(switchblock);

							fall.Instructions.RemoveAt(index2 - 1);
							fall.Instructions.RemoveAt(index2 - 1);
							fall.SetNewFallThrough(switchblock);
							target.DisconnectFromTargets();
							target.Instructions.Clear();
							i++;
						}
					}
					else if (index1 != -1 && index2 == -1) {
						target.DisconnectFromTargets();
						target.Instructions.Clear();
						fall.SetNewFallThrough(switchblock);
					}
					else {
						if (fall.LastInstr.IsConditionalBranch()) {
							index1 = GetStLocIndex(fall.FallThrough.Instructions, locals, local1index);
							if (index1 != -1) {
								target.DisconnectFromTargets();
								target.Instructions.Clear();
								fall.FallThrough.SetNewFallThrough(switchblock);
							}
						}
						target.DisconnectFromTargets();
						target.Instructions.Clear();
					}
				}
			}

			foreach (var block in blocks2) {
				if (block.Value.FallThrough != null)
					block.Value.FallThrough.RemoveGuaranteedDeadBlock();
				block.Value.RemoveGuaranteedDeadBlock();
				while (block.Value.Sources.Count > 0) {
					block.Value.Sources[0].DisconnectFromFallThroughAndTargets();
				}
			}
		}
		private void ResolveFields(List<Block> blocks) {
			foreach (var block in blocks) {
				var instructions = block.Instructions;
				for (int i = 0; i < instructions.Count; i++) {
					if (instructions[i].OpCode != OpCodes.Ldsfld)
						continue;

					FieldDef fieldDef = instructions[i].Operand as FieldDef;
					if (intfields.TryGetValue(fieldDef.MDToken.Raw, out int value)) {
						instructions[i] = new Instr(Instruction.CreateLdcI4(value));
					}
				}
			}
		}
		private int GetStLocIndex(List<Instr> instrs, LocalList locals, int localIndex) {
			for (int i = 0; i < instrs.Count; i++) {
				if (instrs[i].IsStloc() && instrs[i].Instruction.GetLocal(locals).Index == localIndex)
					return i;
			}
			return -1;
		}
		private Dictionary<int, Block> GetBlock(List<Block> blocks, LocalList locals, int index) {
			Dictionary<int, Block> result = new Dictionary<int, Block>();
			try {
				foreach (Block block in blocks) {
					if (!block.LastInstr.IsBrfalse())
						continue;

					int number = 0;
					if (!IsIfBlock(block.Instructions, locals, index, out number))
						continue;

					result[number] = block;
				}
			}
			catch (ArgumentException e) {
				Console.WriteLine("ERROR <GetBlock>: " + e.Message);
				return null;
			}

			return result;
		}
		private bool IsIfBlock(List<Instr> instrs, LocalList locals, int index, out int number) {
			number = 0;
			if (instrs.Count < 4) return false;

			for (int i = 0; i < instrs.Count - 3; i++) {
				if (!instrs[i].Instruction.IsLdloc())
					continue;
				if (instrs[i + 1].Instruction.OpCode != OpCodes.Ldsfld)
					continue;
				if (instrs[i + 2].Instruction.OpCode != OpCodes.Ceq)
					continue;
				if (instrs[i].Instruction.GetLocal(locals).Index != index)
					continue;

				number = GetIntFromFields(instrs[i + 1].Instruction);
				return true;
			}
			return false;
		}
		private int GetIntFromFields(Instruction instr) {
			var field = instr.Operand as FieldDef;
			if (intfields.TryGetValue(field.MDToken.Raw, out int value))
				return value;

			Console.WriteLine("ERROR GetIntFromFields()");
			return -1;
		}
		private bool IsCflow(MethodDef method) {
			var instrs = method.Body.Instructions;
			if (instrs[0].OpCode == OpCodes.Ldsfld &&
				instrs[1].IsStloc() &&
				instrs[2].IsBr() &&
				instrs[3].OpCode == OpCodes.Nop &&
				instrs[4].IsLdloc() &&
				instrs[5].OpCode == OpCodes.Ldsfld &&
				instrs[6].OpCode == OpCodes.Ceq &&
				instrs[7].IsBrfalse())
				return true;
			return false;
		}
		private Dictionary<uint, int> GetFieldsDictionary() {
			Dictionary<uint, int> result = new Dictionary<uint, int>();
			MethodDef cctor = GetModuleCctor();
			if (cctor == null || !cctor.HasBody)
				return result;

			var instructions = cctor.Body.Instructions;
			for (int i = 0; i < instructions.Count - 1; i++) {
				if (instructions[i].IsLdcI4() && instructions[i + 1].OpCode == OpCodes.Stsfld) {
					var field = instructions[i + 1].Operand as FieldDef;
					result[field.MDToken.Raw] = instructions[i].GetLdcI4Value();
				}
			}
			return result;
		}
		private MethodDef GetModuleCctor() {
			// Dapatkan tipe <Module>
			TypeDef moduleType = this.module.GlobalType;

			if (moduleType == null)
				return null;

			// Cari metode dengan IsStaticConstructor
			foreach (MethodDef method in moduleType.Methods) {
				if (method.IsStaticConstructor) {
					return method; // Return method .cctor jika ditemukan
				}
			}

			// Jika tidak ditemukan
			return null;
		}
	}
}
