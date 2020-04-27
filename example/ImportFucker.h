#pragma once

#ifndef _IMPORT_FUCKER
#define _IMPORT_FUCKER

#include <Windows.h>
#include <string>
#include <map>
#include <iterator>


namespace import_fucker
{

	


	/**
	* @description Set the target module that has the function that you want hook.
	* @param {string?} The module name that's the target
	* @returns {bool} return true if it worked
	*/
	bool set_target_module                ( std::string module_name	= ""																				    );
	/**
	* @description Set hook on the function that you wantThe function name that you want ho
	* @param {int} The hook function address
	* @param {string?} The target function name
	* @param {string?} if you're using a target function that is imported by ordinal number you have to set the dll that contains it
	* @param {int?} The target function ordinal number
	* @returns {bool} return true if it worked
	*/
	bool hook			                  ( uintptr_t hook_addr, std::string function_name = "", std::string dll_target_name = "", int32_t ordinal_func = 0 );
	/**
	* @description Removes the hook from target function 
	* @param {string?} The target function name
	* @param {string?} if you're using a target function that is imported by ordinal number you have to set the dll that contains it
	* @param {int?} The target function ordinal number
	* @returns {bool} return true if it worked
	*/
	bool remove_hook	                   ( std::string function_name = "", std::string dll_target_name = "", int32_t ordinal_func = 0					    );

	/**
	* @description Removes the hook from target function
	* @param {string?} The target function name
	* @param {string?} if you're using a target function that is imported by ordinal number you have to set the dll that contains it
	* @param {int?} The target function ordinal number
	* @returns {uintptr_t} return the real_addr if it worked or 0 if doesn't worked.
	*/
	uintptr_t get_hooked_func_real_address ( std::string function_name = "", std::string dll_target_name = "", int32_t ordinal_func = 0                     );
}

#endif