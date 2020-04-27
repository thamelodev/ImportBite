#include "ImportFucker.h"
#pragma once

namespace import_fucker
{
	PIMAGE_DOS_HEADER				 dos_header;
	PIMAGE_NT_HEADERS				 nt_headers;
	PIMAGE_OPTIONAL_HEADER			 op_header;
	PIMAGE_DATA_DIRECTORY			 data_dir;
	PIMAGE_IMPORT_DESCRIPTOR		 import_descriptor;
	std::string						 module_target;

	// Stores real addresses of hooked functions
	std::map<std::string, uintptr_t> hooked_funcs;
}

bool import_fucker::set_target_module( std::string module_name )
{
	// Check if module name is empty if it's we'll set our own module as the target
	if ( !module_name.empty( ) )
	{
		// Check if module exists
		if ( !GetModuleHandleA( module_name.c_str( ) ) )
			return false;

		// Get DOS Header
		import_fucker::dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( GetModuleHandleA( module_name.c_str( ) ) );
	}
	else
		// Get DOS Header of our own module
		import_fucker::dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( GetModuleHandleA( nullptr ) );
	

	
	// Get NT Header
	import_fucker::nt_headers        = reinterpret_cast< PIMAGE_NT_HEADERS >( ( char* ) import_fucker::dos_header + import_fucker::dos_header->e_lfanew );
	// Get Optional Header
	import_fucker::op_header	     = &import_fucker::nt_headers->OptionalHeader;
	// Get Data Directory
	import_fucker::data_dir	         = import_fucker::op_header->DataDirectory;
	// Get Import Directory Table
	import_fucker::import_descriptor = reinterpret_cast< PIMAGE_IMPORT_DESCRIPTOR >( ( char* ) import_fucker::dos_header + import_fucker::data_dir[1].VirtualAddress);

	return true;
}

bool import_fucker::hook( uintptr_t hook_addr, std::string function_name, std::string dll_target_name, int32_t ordinal_func )
{
	// Look up table
	PIMAGE_THUNK_DATA	  import_lookup_tbl    = nullptr;
	// Hint/Name Table
	PIMAGE_IMPORT_BY_NAME target_func_name     = nullptr;
	// Import Address Table
	PIMAGE_THUNK_DATA	  import_address_table = nullptr;


	for ( int i = 0; ; ++i )
	{	
		// Check if the look up table RVA is null
		if ( !import_fucker::import_descriptor [ i ].OriginalFirstThunk )
			return false;

		// Fill import look up table
		import_lookup_tbl = reinterpret_cast< PIMAGE_THUNK_DATA >( import_fucker::import_descriptor [ i ].OriginalFirstThunk + ( char* ) import_fucker::dos_header );
		
		for ( int j = 0; ; ++j )
		{
			// Check if import look up table is null meaning that that's the last lookup table
			if ( !import_lookup_tbl [ j ].u1.AddressOfData )
				break;
			
			// Check if the import look up table selected isn't using ordinal import, if it's not get function name on look up table by Hint/Name Table RVA
			if ( !( import_lookup_tbl [ j ].u1.AddressOfData & IMAGE_ORDINAL_FLAG ) )
				target_func_name = reinterpret_cast< PIMAGE_IMPORT_BY_NAME >( import_lookup_tbl [ j ].u1.AddressOfData + ( char* ) import_fucker::dos_header );
			
			// If it's using ordinal import, compares with target function ordinal number
			else if ( ( import_lookup_tbl [ j ].u1.AddressOfData & 0xFFFF ) == ordinal_func )
			{
				// Get DLL name on Import Directory Table by RVA
				auto dll_name = reinterpret_cast< char* >( import_fucker::import_descriptor [ i ].Name + ( char* ) import_fucker::dos_header );

				// Checks if the dll_name is equal to target dll name
				if ( dll_name != dll_target_name.c_str( ) )
					continue;

				// Fill IAT pointer by Import Directory Table RVA
				import_address_table = reinterpret_cast< PIMAGE_THUNK_DATA >( import_fucker::import_descriptor [ i ].FirstThunk + ( char* ) import_fucker::dos_header );

				DWORD old_protect = { 0 };

				// Change address range protection because need to change to PAGE_READWRITE if we wan't overwrite the address on IAT
				if ( !VirtualProtect( import_address_table + j, 4, PAGE_READWRITE, &old_protect ) )
					return false;

				// Convert ordinal number to string because I'll save it as key inside the hooked_funcs map
				auto ordinal_string = std::to_string( ordinal_func );

				// Get target function real address
				auto func_real_addr = *reinterpret_cast< uintptr_t* >( import_address_table + j );

				// Stores the hooked function real address with the name/ordinal number as key and real address as value
				import_fucker::hooked_funcs.insert( std::pair<std::string, uintptr_t>( ordinal_string, func_real_addr ) );

				// The magic happens here, I simply swap the address on IAT to my hook function
				*reinterpret_cast< uintptr_t* >( import_address_table + j ) = hook_addr;

				// Set back the address range protection to the oldest
				if ( !VirtualProtect( import_address_table + j, 4, old_protect, &old_protect ) )
					return false;

				return true;
			}

			// Check if the name on Hint/Name Table is equal to the function name that I want, if it isn't continue the loop and checks if i'm using ordinal func. (just for sanity idk)
			if ( target_func_name->Name != function_name || ordinal_func )
				continue;
			else
			{
				// Fill IAT pointer by Import Directory Table RVA 
				import_address_table = reinterpret_cast< PIMAGE_THUNK_DATA >( import_fucker::import_descriptor [ i ].FirstThunk + ( char* ) import_fucker::dos_header );

				DWORD old_protect = { 0 };

				// Change address range protection because need to change to PAGE_READWRITE if we wan't overwrite the address on IAT
				if ( !VirtualProtect( import_address_table + j, 4, PAGE_READWRITE, &old_protect ) )
					return false;

				// Get target function real address
				auto func_real_addr = *reinterpret_cast< uintptr_t* >( import_address_table + j );

				// Stores the hooked function real address with the name/ordinal number as key and real address as value
				import_fucker::hooked_funcs.insert( std::pair<std::string, uintptr_t>( function_name, func_real_addr ) );

				// The magic happens here, I simply swap the address on IAT to my hook function
				*reinterpret_cast< uintptr_t* >( import_address_table + j ) = hook_addr;

				// Set back the address range protection to the oldest
				if ( !VirtualProtect( import_address_table + j, 4, old_protect, &old_protect ) )
					return false;

				return true;
			}
			
		}
	}


	return false;
}

bool import_fucker::remove_hook( std::string function_name, std::string dll_target_name, int32_t ordinal_func )
{
	// Checks if i'm using ordinal target func
	if ( ordinal_func )
	{
		// Get hooked function real address using the map
		const auto real_addr = import_fucker::hooked_funcs.find( std::to_string( ordinal_func ) )->second;

		// And use our precious function to unhook
		if ( import_fucker::hook( real_addr, 0, dll_target_name, ordinal_func ) )
		{
			import_fucker::hooked_funcs.erase( function_name );
			return true;
		}
		else
			return false;
	}

	// Checks if function name is empty
	if ( !function_name.empty( ) )
	{
		// Get hooked function real address using the map
		const auto real_addr = import_fucker::hooked_funcs.find( function_name )->second;

		// And use our precious function to unhook
		if ( import_fucker::hook( real_addr, function_name ) )
		{
			import_fucker::hooked_funcs.erase( function_name );
			return true;
		}
		else
			return false;
	}

	return false;
}

uintptr_t import_fucker::get_hooked_func_real_address( std::string function_name, std::string dll_target_name, int32_t ordinal_func )
{
	// Checks if i'm using ordinal target func
	if ( ordinal_func )
	{
		// Get hooked function real address using the map
		const auto real_addr = import_fucker::hooked_funcs.find( std::to_string( ordinal_func ) )->second;

		// If real address was found returns it 
		if ( real_addr )
			return real_addr;
		else
			return 0;
	}

	// Checks if function name is empty
	if ( !function_name.empty( ) )
	{
		// Get hooked function real address using the map
		const auto real_addr = import_fucker::hooked_funcs.find( function_name )->second;

		// If real address was found returns it 
		if ( real_addr )
			return real_addr;
		else
			return 0;
	}
}