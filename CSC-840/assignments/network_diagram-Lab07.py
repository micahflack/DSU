from diagrams import Cluster, Diagram, Edge
import diagrams.onprem.network as OnPremNet
import diagrams.onprem.compute as OnPremCom
import diagrams.generic.os as GenericOS
import diagrams.generic.network as GenericNet

with Diagram("Lab 07 - Network Diagram"):

    vCloud_Internet = OnPremNet.Internet("vCloud Internet", style="bold")

    LAN_2000 = GenericNet.Subnet("LAN_2000: DHCP 172.16.2.2-254")

    LAN_3000 = GenericNet.Subnet("LAN_3000: DHCP 172.16.33.2-254")

    with Cluster("LAN_Internet"):
        pfSense_Gateway = OnPremNet.Pfsense("pfSense_Gateway", style="bold")
        LAN_Internet = GenericNet.Subnet("LAN_Internet: DHCP 10.0.0.100-254")

        vCloud_Internet >> Edge(color="black", xlabel="vmx0 - DHCP", minlen="6") >> pfSense_Gateway
        pfSense_Gateway >> Edge(color="black", xlabel="vmx1 - 10.0.0.1/24", minlen="6") >> LAN_Internet

        with Cluster("LAN_Dev"):
            FreeBSD = GenericOS.LinuxGeneral("FreeBSD", style="bold")
            Ubuntu = GenericOS.Ubuntu("Admin", style="bold")
            LAN_Dev = GenericNet.Subnet("LAN_Dev: DHCP 172.16.1.100-254")

            pfSense_Dev = OnPremNet.Pfsense("pfSense_Dev", style="bold")

            LAN_Internet >> Edge(color="black", xlabel="vmx0 - 10.0.0.100") >> Ubuntu
            LAN_Internet >> Edge(color="black", xlabel="vmx0 - 10.0.0.200") >> FreeBSD

            pfSense_Dev >> Edge(color="black", label="vmx1 - 172.16.1.1/24") >> LAN_Dev

            LAN_Dev >> Edge(color="black", label="vmx1 - 172.16.1.100") >> Ubuntu
            LAN_Dev >> Edge(color="black", label="vmx1 - 172.16.1.200", minlen="2") >> FreeBSD

    with Cluster("BGP_WAN"):
        pfSense_2000 = OnPremNet.Pfsense("pfSense_2000", style="bold")
        pfSense_3000 = OnPremNet.Pfsense("pfSense_3000", style="bold")

        LAN_Internet >> Edge(color="black", label="vmx0 - 10.0.0.2") >> pfSense_Dev

        pfSense_3000 >> Edge(color="black", xlabel="pfSense_3000 - 2001:23:23:23::2/64\t\t\t\npfSense_2000 - 2001:23:23:23::1/64\t\t\t\n\n\n", minlen="8") >> pfSense_2000
        pfSense_2000 >> Edge(color="black", xlabel="\n\npfSense_2000 - 2001:12:12:12::2/64\npfSense_Dev - 2001:12:12:12::1/64", minlen="2") >> pfSense_Dev

    pfSense_2000 >> Edge(color="black", xlabel="vmx1 - 172.16.2.1", minlen="2") >> LAN_2000
    LAN_2000 >> Edge(color="black", xlabel="vmx1 - 172.16.2.2", minlen="2") >> Ubuntu

    pfSense_3000 >> Edge(color="black", xlabel="vmx1 - 172.16.33.1", minlen="2") >> LAN_3000
    LAN_3000 >> Edge(color="black", xlabel="vmx1 - 172.16.33.2", minlen="2") >> Ubuntu
