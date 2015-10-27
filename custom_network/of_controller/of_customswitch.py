from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
 
log = core.getLogger()
 
class MyComponent (object):
  def __init__ (self):
    core.openflow.addListeners(self)
    self.busy_destinations = []

 
  def _handle_ConnectionUp (self, event):
    log.debug("Switch %s has come up.", dpid_to_str(event.dpid))
    log.debug(".... %s", event.dpid)


  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp

    outport = packet.dst.toTuple()[4]
    if outport is 0:
      return

    # Don't allocate flow to a busy destination
    if outport in self.busy_destinations:
      print "deny flow request from %s -> %s" % (packet_in.in_port, outport)
      return

    print "allocate flow from %s -> %s" % (packet_in.in_port, outport)
    self.busy_destinations.append(outport)
    print self.busy_destinations

    msg = of.ofp_flow_mod()
    msg.buffer_id = packet_in.buffer_id
    msg.idle_timeout=1
    msg.flags = msg.flags | of.OFPFF_SEND_FLOW_REM
    msg.match.in_port = packet_in.in_port
    msg.match.dl_dst = packet.dst
    msg.actions.append(of.ofp_action_output(port=outport))
    event.connection.send(msg)


  def _handle_FlowRemoved (self, event):
    match = event.ofp.match
    inport = match.in_port
    outport = match.dl_dst.toTuple()[4]
    print "delete flow from %s -> %s" % (inport, outport)
    # Remove this destination from allocation array
    if outport in self.busy_destinations:
      self.busy_destinations.remove(outport)
      print self.busy_destinations
 
def launch ():
  core.registerNew(MyComponent)
