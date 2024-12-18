using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using de4dot.blocks;

namespace de4dot.code.deobfuscators.Unknown {
	public static class Utils {
		public static List<MethodDef> GetAllMethodDefs(ModuleDefMD module) {
			List<MethodDef> allMethods = new List<MethodDef>();

			// Iterate through all types in the module
			foreach (TypeDef type in module.GetTypes()) {
				// Recursively get all methods for the type and its nested types
				GetAllMethodsRecursive(type, allMethods);
			}

			return allMethods;
		}
		private static void GetAllMethodsRecursive(TypeDef type, List<MethodDef> allMethods) {
			// Iterate through methods of the type
			foreach (MethodDef method in type.Methods) {
				allMethods.Add(method);
			}

			// Recursively iterate through nested types
			foreach (TypeDef nestedType in type.NestedTypes) {
				GetAllMethodsRecursive(nestedType, allMethods);
			}
		}
		public static MethodDef GetMethodFromToken(ModuleDefMD module, uint targetMethodToken) {
			// Iterate through all types in the module
			foreach (var type in module.Types) {
				MethodDef method = GetMethodByTokenRecursive(type, targetMethodToken);
				if (method != null) {
					return method;
				}
			}

			return null; // Method not found with the given token
		}
		private static MethodDef GetMethodByTokenRecursive(TypeDef typeDef, uint targetMethodToken) {
			foreach (MethodDef method in typeDef.Methods) {
				if (method.MDToken.Raw == targetMethodToken) {
					return method;
				}
			}

			// Recursively iterate through nested types
			foreach (TypeDef nestedType in typeDef.NestedTypes) {
				MethodDef method = GetMethodByTokenRecursive(nestedType, targetMethodToken);
				if (method != null) {
					return method;
				}
			}

			return null;
		}
		public static List<Block> GetAllBlocks(List<BaseBlock> baseBlocks) {
			List<Block> allBlocks = new List<Block>();
			foreach (var baseBlock in baseBlocks) {
				if (baseBlock.GetType() == typeof(TryBlock)) {
					foreach (Block block in ((TryBlock)baseBlock).GetAllBlocks()) {
						allBlocks.Add(block);
					}
				}
				else if (baseBlock.GetType() == typeof(TryHandlerBlock)) {
					foreach (Block block in ((TryHandlerBlock)baseBlock).GetAllBlocks()) {
						allBlocks.Add(block);
					}
				}
				else if (baseBlock.GetType() == typeof(Block)) {
					allBlocks.Add((Block)baseBlock);
				}
			}
			return allBlocks;
		}
	}
}
