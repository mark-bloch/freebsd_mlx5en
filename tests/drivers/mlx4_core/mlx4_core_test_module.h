#include <sys/sysctl.h>
// Add here indludes to all test cases' headers
#include "mlx4_core_tests.h"

/************************************/
/******* tests infrastructure *******/
/************************************/

#define BUFF_SIZE       1024

#define TEST_CASE(name, desc, func)  {name, desc, func, NULL}
struct test_case {
        char *name;
        char *desc;
        int (*func) (struct mlx4_dev *dev, char *log);
        struct sysctl_oid *result_oidp;
        char status[BUFF_SIZE];
        char result[BUFF_SIZE];
};

// to add a new test to the system:
// add another TEST_CASE with 3 parameters - name, short description, test entry function
static struct test_case tests[] = {
//		  TEST_CASE("test_name", "test description", starting_function),
		TEST_CASE("db_test", "Door Bell allocation test", db_test),
		TEST_CASE("alloc_hwq_res_test", "Hardware queue resources allocation test", alloc_hwq_res_test),
		TEST_CASE("cmd_test", "cmd : Mailbox allocation test", cmd_test),
		TEST_CASE("bf_test", "Blue Flame allocation test", bf_test),
		TEST_CASE("uar_test", "User Access Region allocation test", uar_test),
		TEST_CASE("xrcd_test", "Extended Reliable Connected Domain allocation test", xrcd_test),
		TEST_CASE("pd_test", "Protection Domain allocation test", pd_test),
		TEST_CASE("qp_to_ready_test", "QP allocation and mlx4_qp_to_ready test", qp_to_ready_test),
                TEST_CASE("qp_modify_test", "QP allocation and mlx4_qp_modify test", qp_modify_test),
		TEST_CASE("mtt_without_pages_test", "MTT allocation test (for zero pages)", mtt_without_pages_test),
                TEST_CASE("mtt_with_pages_test", "MTT allocation and enabling test", mtt_with_pages_test),
                TEST_CASE("mr_test", "MR allocation and enabling test", mr_test),
                TEST_CASE("fmr_test", "FMR allocation, enabling and mapping test", fmr_test),
		TEST_CASE("srq_test", "SRQ allocation, arm and query test", srq_test),
		TEST_CASE("fw_test", "PORT and 'wake on LAN' functionality test", fw_test),
		TEST_CASE("mac_functionality_test", "mac registration, replacement and unregistration test", mac_functionality_test),
                TEST_CASE("vlan_functionality_test", "vlan registration, unregistration and lookup test", vlan_functionality_test),
                TEST_CASE("SET_PORT_general_test", "mlx4_SET_PORT_general function test", SET_PORT_general_test),
		TEST_CASE("SET_PORT_qpn_calc_test", "mlx4_SET_PORT_qpn_calc function test", SET_PORT_qpn_calc_test),
		TEST_CASE("SET_PORT_PRIO2TC_test", "mlx4_SET_PORT_PRIO2TC function test", SET_PORT_PRIO2TC_test),
		TEST_CASE("SET_PORT_SCHEDULER_test", "mlx4_SET_PORT_SCHEDULER function test", SET_PORT_SCHEDULER_test),
		TEST_CASE("SET_MCAST_FLTR_test", "mlx4_SET_MCAST_FLTR function test", SET_MCAST_FLTR_test),
		TEST_CASE("SET_stats_bitmap_test", "mlx4_SET_stats_bitmap function test", SET_stats_bitmap_test),
		TEST_CASE("ipv6_over_ib_steering_mode_B0_multicast_test", "IPV6 over IB with steering mode B0 multicast rule attach and detach test", ipv6_over_ib_steering_mode_B0_multicast_test),
                TEST_CASE("eth_steering_mode_BO_multicast_test", "ETH with steering mode B0 multicast rule attach and detach test", eth_steering_mode_BO_multicast_test),
                TEST_CASE("ib_steering_mode_A0_multicast_test", "ib with steering mode A0 multicast attach and detach test", ib_steering_mode_A0_multicast_test),
                TEST_CASE("ipv6_ib_unicast_test", "ipv6 over ib unicast rule attach and detach test", ipv6_ib_unicast_test),
                TEST_CASE("eth_unicast_test", "ETH unicast rule attach and detach test", eth_unicast_test),
		TEST_CASE("eq_test", "test that verifies accept of interrupts on all the irq vectors of the device", eq_test),
		TEST_CASE("cq_test", "CQ allocation and modification test", cq_test),
};
int num_of_test_cases = sizeof(tests) / sizeof(struct test_case);
