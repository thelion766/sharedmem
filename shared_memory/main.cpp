#include "thread_manager.h"
#include "resolver.h"
#include "functions.h"
#include "gadget.h"
#include "comm_handler.h"


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
	if (!resolver::setup()) 
		return nt_status_t::unsuccessful;

	if (!gadget::execute(comm_handler::thread_routine))
		return nt_status_t::unsuccessful;

	return nt_status_t::success;
}