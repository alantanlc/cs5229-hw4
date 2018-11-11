package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.util.FlowModUtils;
import org.kohsuke.args4j.CmdLineException;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Created by pravein on 28/9/17.
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();
    HashMap<Integer, String> ClientIPDataHashCodeMap = new HashMap<>();	// Use Data hashCode as QueryID
    HashMap<Integer, String> RouterMACDataHashCodeMap = new HashMap<>();

    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }





    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
	
	// Get the Ethernet packet
	Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

	logger.info("dstMACAddress: {}", ethPacket.getDestinationMACAddress());

	if(ethPacket.getEtherType() == EthType.ARP) {
		logger.info("Received an ARP packet!");

		// ARP
		ARP arp = (ARP) ethPacket.getPayload();

		// Handle ARP request
		if(arp.getOpCode() == ARP.OP_REQUEST) {
			return this.handleARPRequest(sw, arp, cntx);
		}
	} else if(ethPacket.getEtherType() == EthType.IPv4) {
		IPv4 ipv4 = (IPv4) ethPacket.getPayload();

		// Handle ICMP packets (ICMP = 0x1)
		if(ipv4.getProtocol() == IpProtocol.ICMP) {
			logger.info("Received an ICMP packet!");

			ICMP i = (ICMP) ipv4.getPayload();
			if(i.getIcmpType() == ICMP.ECHO_REQUEST) {
				return this.handleICMPRequest(sw, ipv4, cntx, ethPacket.getDestinationMACAddress().toString());
			} else {
				return this.handleICMPReply(sw, ipv4, cntx);
			}
		} else {
			logger.info("Received a non-ICMP packet!");
		}
	}

        return Command.CONTINUE;
    }

	// Forward client's ICMP request to server
	protected Command handleICMPRequest(IOFSwitch sw, IPv4 ipv4, FloodlightContext cntx, String dstMACAddress) {
		logger.info("handleICMPRequest");

		IPv4Address dstIp = ipv4.getDestinationAddress();
		IPv4Address srcIp = ipv4.getSourceAddress();
		logger.info("dstIp: {}", dstIp);
		logger.info("srcIp: {}", srcIp);

		if((srcIp.toString().equals("192.168.0.10")
			|| srcIp.toString().equals("192.168.0.20"))
			&& !dstIp.toString().equals("10.0.0.11")) {
				logger.info("Client to client ping not allowed!");
				return Command.CONTINUE;
		}

		ICMP originalIcmp = (ICMP) ipv4.getPayload();
		Data data = new Data(originalIcmp.getPayload().serialize());
		logger.info("Data hashCode: {}", data.hashCode());

		ClientIPDataHashCodeMap.put(data.hashCode(), srcIp.toString());
		RouterMACDataHashCodeMap.put(data.hashCode(), dstMACAddress);

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IpProtocol.ICMP);
		ip.setSourceAddress("10.0.0.1");
		ip.setDestinationAddress(dstIp);
		ip.setPayload(originalIcmp);

		IPacket ethPacket = new Ethernet()
			.setEtherType(EthType.IPv4)
			.setSourceMACAddress("00:23:10:00:00:01")
			.setDestinationMACAddress(IPMacMap.get(dstIp.toString()))
			.setPayload(ip);

		// Send ICMP echo
		byte[] serializedData = ethPacket.serialize();
		OFPacketOut po = sw.getOFFactory().buildPacketOut()
			.setData(serializedData)
			.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))
							.setInPort(OFPort.CONTROLLER).build();
		sw.write(po);

		return Command.CONTINUE;
	}

	// Forward server's ICMP reply to client
	protected Command handleICMPReply(IOFSwitch sw, IPv4 ipv4, FloodlightContext cntx) {
		logger.info("handleICMPReply");

		IPv4Address dstIp = ipv4.getDestinationAddress();
		IPv4Address srcIp = ipv4.getSourceAddress();
		logger.info("dstIp: {}", dstIp);
		logger.info("srcIp: {}", srcIp);

		ICMP originalIcmp = (ICMP) ipv4.getPayload();
		Data data = new Data(originalIcmp.getPayload().serialize());
		logger.info("Data hashCode: {}", data.hashCode());

		// Get client ip address using data hash code
		String clientIp = ClientIPDataHashCodeMap.get(data.hashCode());
		String routerMAC = RouterMACDataHashCodeMap.get(data.hashCode());
	
		IPacket ethPacket = new Ethernet()
			.setEtherType(EthType.IPv4)
			.setSourceMACAddress(routerMAC)
			.setDestinationMACAddress(IPMacMap.get(clientIp));

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IpProtocol.ICMP);
		ip.setSourceAddress(srcIp);
		ip.setDestinationAddress(clientIp);

		ICMP icmp = new ICMP();
		icmp.setIcmpType((byte) 0);
		icmp.setIcmpCode((byte) 0);

		ethPacket.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		// Send ICMP echo
		byte[] serializedData = ethPacket.serialize();
		OFPacketOut po = sw.getOFFactory().buildPacketOut()
			.setData(serializedData)
			.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))
							.setInPort(OFPort.CONTROLLER).build();
		sw.write(po);

		return Command.CONTINUE;
	}

	// Handle incoming ARP packets, sends back ARP reply
	protected Command handleARPRequest(IOFSwitch sw, ARP arp, FloodlightContext cntx) {
		logger.info("handleARPRequest");
		logger.info("ARP: {}", arp.toString());

		// MAC address of the (yet unknown) ARP target
		String targetMACAddress = RouterInterfaceMacMap.get(arp.getTargetProtocolAddress().toString());
		logger.info("targetMACAddress: {}", targetMACAddress);

		// ARP
		ARP arpReply = new ARP()
			.setHardwareType(ARP.HW_TYPE_ETHERNET)
			.setProtocolType(ARP.PROTO_TYPE_IP)
			.setOpCode(ARP.OP_REPLY)
			.setHardwareAddressLength((byte) 6)
			.setProtocolAddressLength((byte) 4)
			.setSenderHardwareAddress(MacAddress.of(targetMACAddress))
			.setSenderProtocolAddress(arp.getTargetProtocolAddress())
			.setTargetHardwareAddress(arp.getSenderHardwareAddress())
			.setTargetProtocolAddress(arp.getSenderProtocolAddress());

		logger.info("arpReply: {}", arpReply.toString());

		// Prepare packet
		IPacket ethPacket = new Ethernet()
			.setSourceMACAddress(targetMACAddress)
			.setDestinationMACAddress(arp.getSenderHardwareAddress())
			.setEtherType(EthType.ARP)
			.setPayload(arpReply);

		// Send ICMP echo
		byte[] serializedData = ethPacket.serialize();
		OFPacketOut po = sw.getOFFactory().buildPacketOut()
			.setData(serializedData)
			.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))
							.setInPort(OFPort.CONTROLLER).build();
		sw.write(po);

		return Command.CONTINUE;
	}

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                return handlePacketIn(sw, (OFPacketIn)msg, cntx);
            default:
                break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);

        // Use the below HashMaps as per your need

        // Router Interface IP to Mac address Mappings
        RouterInterfaceMacMap.put("10.0.0.1","00:23:10:00:00:01");
        RouterInterfaceMacMap.put("192.168.0.1","00:23:10:00:00:02");
        RouterInterfaceMacMap.put("192.168.0.2","00:23:10:00:00:03");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        //Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
