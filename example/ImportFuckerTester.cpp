#include <Windows.h>
#include "ImportFucker.h"


using f_messageboxw = int  ( WINAPI* )( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType );

int WINAPI FakeMessageBox( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType )
{
    Beep( 700, 1500 );

    printf( "Called the hook" );

    system( "pause" );

    f_messageboxw original_messagebow = reinterpret_cast< f_messageboxw >( import_fucker::get_hooked_func_real_address( "MessageBoxW" ) );

    return original_messagebow(nullptr, L"OK", L"OK", MB_CANCELTRYCONTINUE);
}


void run_test( )
{

    MessageBoxW( nullptr, nullptr, nullptr, MB_OK );

    printf( "Real Address: 0x%p\n", &MessageBoxW );

    if ( !import_fucker::set_target_module( "ImportFuckerTester.exe" ) )
    {
        printf( "Error module not found!" );
        system( "pause" );
    }

    if ( !import_fucker::hook( reinterpret_cast< uintptr_t >( &FakeMessageBox ), "MessageBoxW" ) )
    {
        printf( "Func not hooked!" );
        system( "pause" );
    }

    MessageBoxW( nullptr, nullptr, nullptr, MB_OK );

    if ( !import_fucker::remove_hook( "MessageBoxW", "", 0 ) )
    {
        printf( "Func not unhooked!" );
        system( "pause" );
    }

    MessageBoxW( nullptr, nullptr, nullptr, MB_OK );
}


int main()
{
    run_test( );
}
