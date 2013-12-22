#!/usr/bin/python

import sys
import os
import socket
import struct


import array

from netlink import hexdump, parse_attributes, Message, Nested, U8Attr, StrAttr, NulStrAttr, Connection, NETLINK_GENERIC, U32Attr, NLM_F_REQUEST
#from genetlink import Controller, GeNlMessage

NETLINK_ROUTE = 0
RTM_GETDCB = 78
AF_UNSPEC = 0

DCB_CMD_UNDEFINED = 0
DCB_CMD_GSTATE = 1
DCB_CMD_SSTATE = 2
DCB_CMD_PGTX_GCFG = 3
DCB_CMD_PGTX_SCFG = 4
DCB_CMD_PGRX_GCFG = 5
DCB_CMD_PGRX_SCFG = 6
DCB_CMD_PFC_GCFG = 7
DCB_CMD_PFC_SCFG = 8
DCB_CMD_SET_ALL = 9
DCB_CMD_GPERM_HWADDR = 10
DCB_CMD_GCAP = 11
DCB_CMD_GNUMTCS = 12
DCB_CMD_SNUMTCS = 13
DCB_CMD_PFC_GSTATE = 14
DCB_CMD_PFC_SSTATE = 15
DCB_CMD_BCN_GCFG = 16
DCB_CMD_BCN_SCFG = 17
DCB_CMD_GAPP = 18
DCB_CMD_SAPP = 19
DCB_CMD_IEEE_SET = 20
DCB_CMD_IEEE_GET = 21
DCB_CMD_GDCBX = 22
DCB_CMD_SDCBX = 23
DCB_CMD_GFEATCFG = 24
DCB_CMD_SFEATCFG = 25
DCB_CMD_CEE_GET = 26
DCB_CMD_IEEE_DEL = 27

DCB_ATTR_UNDEFINED = 0
DCB_ATTR_IFNAME = 1
DCB_ATTR_STATE = 2
DCB_ATTR_PFC_STATE = 3
DCB_ATTR_PFC_CFG = 4
DCB_ATTR_NUM_TC = 5
DCB_ATTR_PG_CFG = 6
DCB_ATTR_SET_ALL = 7
DCB_ATTR_PERM_HWADDR = 8
DCB_ATTR_CAP = 9
DCB_ATTR_NUMTCS = 10
DCB_ATTR_BCN = 11
DCB_ATTR_APP = 12
DCB_ATTR_IEEE = 13
DCB_ATTR_DCBX = 14
DCB_ATTR_FEATCFG = 15
DCB_ATTR_CEE = 16

DCB_ATTR_IEEE_UNSPEC = 0
DCB_ATTR_IEEE_ETS = 1
DCB_ATTR_IEEE_PFC = 2
DCB_ATTR_IEEE_APP_TABLE = 3
DCB_ATTR_IEEE_PEER_ETS = 4
DCB_ATTR_IEEE_PEER_PFC = 5
DCB_ATTR_IEEE_PEER_APP = 6
DCB_ATTR_IEEE_MAXRATE = 7

class DcbnlHdr:
    def __init__(self, len, type):
        self.len = len
        self.type = type
    def _dump(self):
        return struct.pack("BBxx", self.len, self.type)

class DcbNlMessage(Message):
    def __init__(self, type, cmd, attrs=[], flags=0):
        self.type = type
        self.cmd = cmd
        self.attrs = attrs
        Message.__init__(self, type, flags=flags,
                         payload=[DcbnlHdr(len=0, type=self.cmd)]+attrs)

    @staticmethod
    def recv(conn):
        msgs = conn.recv()
        packet = msgs[0].payload

	dcb_family, cmd = struct.unpack("BBxx", packet[:4])

        dcbnlmsg = DcbNlMessage(dcb_family, cmd)
        dcbnlmsg.attrs = parse_attributes(packet[4:])

        return dcbnlmsg

class DcbController:
	def __init__(self, intf):
		self.conn = Connection(NETLINK_ROUTE)
		self.intf = intf

	def check_err(self, m, attr_type):
		if m.attrs[attr_type].u8():
			err = OSError("Netlink error: Bad value. see dmesg.")
                    	raise err

	def get_dcb_state(self):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_GSTATE,
				flags=NLM_F_REQUEST, attrs=[a])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		return m.attrs[0].u8()

	def set_dcb_state(self, state):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		state_attr = U8Attr(DCB_ATTR_STATE, state)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_SSTATE,
				flags=NLM_F_REQUEST, attrs=[a, state_attr])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		self.check_err(m, DCB_ATTR_STATE)

	def get_dcbx(self):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_GDCBX,
				flags=NLM_F_REQUEST, attrs=[a])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		return m.attrs[DCB_ATTR_DCBX].u8()

	def set_dcbx(self, mode):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		mode_attr = U8Attr(DCB_ATTR_DCBX , mode)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_SDCBX,
				flags=NLM_F_REQUEST, attrs=[a, mode_attr])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		self.check_err(m, DCB_ATTR_DCBX)

	def get_ieee_ets(self):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_IEEE_GET,
				flags=NLM_F_REQUEST, attrs=[a])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)

		ieee_nested = m.attrs[DCB_ATTR_IEEE]

		ieee = m.attrs[DCB_ATTR_IEEE].nested()

		willing, ets_cap, cbs = struct.unpack_from("BBB", ieee[DCB_ATTR_IEEE_ETS].str(), 0)

		a = array.array('B')
		a.fromstring(ieee[DCB_ATTR_IEEE_ETS].str()[3:])

		f = lambda A, n=8: [A[i:i+n] for i in range(0, len(A), n)]

		tc_tc_bw, tc_rx_bw, tc_tsa, prio_tc, tc_reco_bw, tc_reco_tsa, reco_prio_tc = f(a,8)

		return prio_tc, tc_tsa, tc_tc_bw

	def set_ieee_ets(self, _prio_tc, _tsa, _tc_bw):
		willing = 0
		ets_cap = 0
		cbs = 0
		tc_rx_bw = array.array('B', '\0' * 8)
		tc_reco_bw = array.array('B', '\0' * 8)
		tc_reco_tsa = array.array('B', '\0' * 8)
		reco_prio_tc = array.array('B', '\0' * 8)

		tc_tc_bw = array.array('B', '\0' * 8)
		tc_tsa = array.array('B', '\0' * 8)
		prio_tc = array.array('B', '\0' * 8)

		for up in range(len(_prio_tc)): prio_tc[up] = _prio_tc[up] 
		for tc in range(len(_tsa)): tc_tsa[tc] = _tsa[tc]
		for tc in range(len(_tc_bw)): tc_tc_bw[tc] = _tc_bw[tc]
			
		ets = struct.pack("BBB", willing, ets_cap, cbs) + (tc_tc_bw + tc_rx_bw +
				tc_tsa + prio_tc + tc_reco_bw + tc_reco_tsa + 
				reco_prio_tc).tostring()

		intf = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		ieee_ets = StrAttr(DCB_ATTR_IEEE_ETS, ets)
		ieee = Nested(DCB_ATTR_IEEE, [ieee_ets]);

		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_IEEE_SET,
				flags=NLM_F_REQUEST, attrs=[intf, ieee])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		self.check_err(m, DCB_ATTR_IEEE)

	def get_ieee_maxrate(self):
		a = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_IEEE_GET,
				flags=NLM_F_REQUEST, attrs=[a])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)

		ieee_nested = m.attrs[DCB_ATTR_IEEE]

		ieee = m.attrs[DCB_ATTR_IEEE].nested()

                tc_maxrate = struct.unpack_from("QQQQQQQQ",ieee[DCB_ATTR_IEEE_MAXRATE].str(), 0);

		return tc_maxrate

	def set_ieee_maxrate(self, _tc_maxrate):
                tc_maxrate = struct.pack("QQQQQQQQ",
                        _tc_maxrate[0],
                        _tc_maxrate[1],
                        _tc_maxrate[2],
                        _tc_maxrate[3],
                        _tc_maxrate[4],
                        _tc_maxrate[5],
                        _tc_maxrate[6],
                        _tc_maxrate[7],
                        )

		intf = NulStrAttr(DCB_ATTR_IFNAME, self.intf)
		ieee_maxrate = StrAttr(DCB_ATTR_IEEE_MAXRATE, tc_maxrate)
		ieee = Nested(DCB_ATTR_IEEE, [ieee_maxrate]);

		m = DcbNlMessage(type = RTM_GETDCB, cmd = DCB_CMD_IEEE_SET,
				flags=NLM_F_REQUEST, attrs=[intf, ieee])
		m.send(self.conn)
		m = DcbNlMessage.recv(self.conn)
		self.check_err(m, DCB_ATTR_IEEE)
