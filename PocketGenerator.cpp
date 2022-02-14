#include "PocketGenerator.h"
#include <iostream>

using namespace std;

PocketGenerator::PocketGenerator(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	all_interface();

	ethernet_header.clear();
	ip_header.clear();
	udp_header.clear();
	tcp_header.clear();
	icmp_header.clear();

	ui.tabWidget->setCurrentIndex(3);

	ethernet_header.type = 0x0008;
}

struct interfaces {
	int index;
	char* name;
	pcap_if_t* dev;
};
vector<interfaces> interfs;
vector<packet_builder> packets;


void PocketGenerator::all_interface()
{
	char errbuf[256];
	pcap_if_t* devlist;
	pcap_if_t* dev;
	pcap_t* pcap_interface = NULL;
	int index = 0;
	interfs.resize(1);
	pcap_findalldevs(&devlist, errbuf);
	for (dev = devlist; dev; dev = dev->next)
	{
		interfs[index].index = index;
		interfs[index].dev = dev;
		interfs[index].name = new char[256];
		strcpy(interfs[index].name, dev->name);
		ui.select_interface->addItem(dev->description);
		index++;
		interfs.resize(index + 1);
	}
	on_select_interface_currentIndexChanged(0);
}

void PocketGenerator::on_select_interface_currentIndexChanged(int index)
{
	char errbuf[256];
	
	if ((pcap_interface = pcap_open_live(interfs[index].dev->name,
		65536 /*snaplen*/,
		1 /*flags, 1=promiscuous, 0=not promiscuous*/,
		1000 /*read timeout*/,
		errbuf)
		) == NULL)
	{
		cerr << endl << "Unable to open the adapter." << endl;
	}
}

void PocketGenerator::on_push_button_packet_clicked()
{
	QString protos[4] = { "ICMP: ", "TCP: ", "UDP: ", "IP:  " };
	on_push_button_auto_val_clicked();
	packets.push_back(PB);
	
	QString pckt_str = QString::number(packets.size()) + ": " + protos[ui.tabWidget->currentIndex()];

	for (int i = 0; i < (PB.packet_size < 35 ? PB.packet_size : 35); i++)
	{
		if (PB.packet[i] < 16) pckt_str += '0';
		pckt_str += QString::number(PB.packet[i] & 0xff, 16) + " ";
	}
	if (PB.packet_size > 35) pckt_str += "...";
	ui.textEdit->append(pckt_str);
	
	
	QString data_str = "";
	for (int i = 0; i < PB.packet_size; i++)
	{
		if (PB.packet[i] < 16) data_str += '0';
		data_str += QString::number(PB.packet[i] & 0xff, 16) + " ";
	}
	ui.text_hex_view->setText(data_str);
}

void PocketGenerator::on_button_clear_seq_clicked()
{
	packets.clear();
	ui.textEdit->clear();
}

void PocketGenerator::on_send_seq_button_packet_clicked()
{
	//ui.textEdit->append("on_send_seq_button_packet_clicked");
	for (int i = 0; i < packets.size(); i++)
	{
		pcap_sendpacket(pcap_interface, packets[i].packet, packets[i].packet_size);
	}
}
//
void PocketGenerator::on_tabWidget_currentChanged(int index)
{
	
	if (index == 0)
	{
		PB.prot = IPPROTO_ICMP;
	} 
	else if (index == 1)
	{
		PB.prot = IPPROTO_TCP;
	}
	else if (index == 2)
	{
		PB.prot = IPPROTO_UDP;
	}
	else if (index == 3)
	{
		PB.prot = IPPROTO_IP;
	}
}


#pragma region IP
//
void PocketGenerator::on_line_hlen_ip_editingFinished()
{
	BYTE val;
	val = ui.line_hlen_ip->text().toUShort();
	ip_header.hdr_len = val & 0x0F;
}
//
void PocketGenerator::on_line_version_ip_editingFinished()
{
	BYTE val;
	val = ui.line_version_ip->text().toUShort();
	ip_header.version = val & 0x0F;
}
//
void PocketGenerator::on_line_tos_ip_editingFinished()
{
	BYTE val;
	val = ui.line_tos_ip->text().toUShort();
	ip_header.tos = val;
}
//
void PocketGenerator::on_line_length_ip_editingFinished()
{
	WORD val;
	val = ui.line_length_ip->text().toUInt();
	ip_header.length = htons(val);
	//ui.textEdit->append("ip_header.length");
}
//
void PocketGenerator::on_line_id_ip_editingFinished()
{
	WORD val;
	val = ui.line_id_ip->text().toUInt();
	ip_header.id = htons(val);
}
//
void PocketGenerator::on_check_mf_ip_stateChanged(int val)
{
	ip_header.more_frag = val ? true : false;
}
//
void PocketGenerator::on_check_df_ip_stateChanged(int val)
{
	ip_header.dont_frag = val ? true : false;
}
//
void PocketGenerator::on_check_zero_ip_stateChanged(int val)
{
	ip_header.reserved = val ? true : false;
}
//
void PocketGenerator::on_line_offset_ip_editingFinished()
{
	WORD val;
	val = ui.line_offset_ip->text().toUInt();
	ip_header.frag_offset_l = val & 0x00ff;
	ip_header.frag_offset_h = (val >> 8) & 0x1f;
}
//
void PocketGenerator::on_line_ttl_ip_editingFinished()
{
	BYTE val;
	val = ui.line_ttl_ip->text().toUShort();
	ip_header.ttl = val;
}
//
void PocketGenerator::on_line_protocol_ip_editingFinished()
{
	BYTE val;
	val = ui.line_protocol_ip->text().toUShort();
	ip_header.proto = val;
}
//
void PocketGenerator::on_line_checksum_ip_editingFinished()
{
	WORD val;
	val = ui.line_checksum_ip->text().toUInt();
	ip_header.csum = val;
}
//
void PocketGenerator::on_line_src_ip_editingFinished()
{
	ip_header.src_addr = inet_addr(ui.line_src_ip->text().toStdString().data());
	
	DWORD ret;
	IPAddr srcip = 0;
	ULONG PhyAddrLen = 6;
	
	ret = SendARP(ip_header.src_addr, srcip, ethernet_header.src_mac, &PhyAddrLen);
	
	if (ret)
	{
		memset(ethernet_header.src_mac, -1, 6 * sizeof(BYTE));
	}

	ui.line_src_mac->setText(ethernet_header.src_mac_toQstring());
}
//
void PocketGenerator::on_line_dst_ip_editingFinished()
{
	ip_header.dst_addr = inet_addr(ui.line_dst_ip->text().toStdString().data());

	DWORD ret;
	IPAddr srcip = 0;
	ULONG PhyAddrLen = 6;

	ret = SendARP(ip_header.dst_addr, srcip, ethernet_header.dst_mac, &PhyAddrLen);

	if (ret)
	{
		memset(ethernet_header.dst_mac, -1, 6 * sizeof(BYTE));
	}

	ui.line_dst_mac->setText(ethernet_header.dst_mac_toQstring());
}

#pragma endregion

#pragma region ICMP

void PocketGenerator::on_line_type_icmp_editingFinished()
{
	BYTE val;
	val = ui.line_type_icmp->text().toUShort();
	icmp_header.type = val;
}

void PocketGenerator::on_line_code_icmp_editingFinished()
{
	BYTE val;
	val = ui.line_code_icmp->text().toUShort();
	icmp_header.code = val;
}

void PocketGenerator::on_line_checksum_icmp_editingFinished()
{
	WORD val;
	val = ui.line_checksum_icmp->text().toUInt();
	icmp_header.csum = val;
}

void PocketGenerator::on_line_id_icmp_editingFinished()
{
	WORD val;
	val = ui.line_id_icmp->text().toUInt();
	icmp_header.id = htons(val);
}

void PocketGenerator::on_line_seq_icmp_editingFinished()
{
	WORD val;
	val = ui.line_seq_icmp->text().toUInt();
	icmp_header.seq = htons(val);
}

#pragma endregion

#pragma region TCP

void PocketGenerator::on_line_src_tcp_editingFinished()
{
	WORD val;
	val = ui.line_src_tcp->text().toUInt();
	tcp_header.src_port = htons(val);
}

void PocketGenerator::on_line_dst_tcp_editingFinished()
{
	WORD val;
	val = ui.line_dst_tcp->text().toUInt();
	tcp_header.dst_port = htons(val);
}

void PocketGenerator::on_line_seq_num_tcp_editingFinished()
{
	DWORD val;
	val = ui.line_seq_num_tcp->text().toUInt(); //toUInt DWORD
	tcp_header.seq = htonl(val);
}

void PocketGenerator::on_line_ack_num_tcp_editingFinished()
{
	DWORD val;
	val = ui.line_ack_num_tcp->text().toUInt(); //toUInt DWORD
	tcp_header.ack_knowledge = htonl(val);
}



void PocketGenerator::on_line_hlen_tcp_editingFinished()
{
	BYTE val;
	val = ui.line_hlen_tcp->text().toUShort();
	tcp_header.hdr_len = val & 0x0f;
}



void PocketGenerator::on_line_win_tcp_editingFinished()
{
	WORD val;
	val = ui.line_win_tcp->text().toUInt();
	tcp_header.window = htons(val);
}

void PocketGenerator::on_line_csum_tcp_editingFinished()
{
	WORD val;
	val = ui.line_csum_tcp->text().toUInt();
	tcp_header.csum = val;
}

void PocketGenerator::on_line_upoint_tcp_editingFinished()
{
	WORD val;
	val = ui.line_upoint_tcp->text().toUInt();
	tcp_header.urg_ptr = htons(val);
}

#	pragma region TCP_FLAGS
//
void PocketGenerator::on_check_ns_tcp_stateChanged(int val)
{
	tcp_header.ns = val ? true : false;
}
//
void PocketGenerator::on_check_cwr_tcp_stateChanged(int val)
{
	tcp_header.cwr = val ? true : false;
}
//
void PocketGenerator::on_check_ece_tcp_stateChanged(int val)
{
	tcp_header.ecn = val ? true : false;
}
//
void PocketGenerator::on_check_urg_tcp_stateChanged(int val)
{
	tcp_header.urg = val ? true : false;
}
//
void PocketGenerator::on_check_ack_tcp_stateChanged(int val)
{
	tcp_header.ack = val ? true : false;
}
//
void PocketGenerator::on_check_psh_tcp_stateChanged(int val)
{
	tcp_header.psh = val ? true : false;
}
//
void PocketGenerator::on_check_rst_tcp_stateChanged(int val)
{
	tcp_header.rst = val ? true : false;
}
//
void PocketGenerator::on_check_syn_tcp_stateChanged(int val)
{
	tcp_header.syn = val ? true : false;
}
//
void PocketGenerator::on_check_fin_tcp_stateChanged(int val)
{
	tcp_header.fin = val ? true : false;
}
#	pragma endregion

#pragma endregion

#pragma region UDP

void PocketGenerator::on_line_src_udp_editingFinished()
{
	WORD val;
	val = ui.line_src_udp->text().toUInt();
	udp_header.src_port = htons(val);
}

void PocketGenerator::on_line_dst_udp_editingFinished()
{
	WORD val;
	val = ui.line_dst_udp->text().toUInt();
	udp_header.dst_port = htons(val);
}

void PocketGenerator::on_line_length_udp_editingFinished()
{
	WORD val;
	val = ui.line_length_udp->text().toUInt();
	udp_header.length = htons(val);
}

void PocketGenerator::on_line_csum_udp_editingFinished()
{
	WORD val;
	val = ui.line_csum_udp->text().toUInt();
	udp_header.csum = val;
}

#pragma endregion

#pragma region AUTO_VAL

void PocketGenerator::on_check_proto_auto_ip_stateChanged(int val)
{
	ui.line_protocol_ip->setDisabled(val);
}

void PocketGenerator::on_check_length_auto_ip_stateChanged(int val)
{
	ui.line_length_ip->setDisabled(val);
}

void PocketGenerator::on_check_csum_auto_ip_stateChanged(int val)
{
	ui.line_checksum_ip->setDisabled(val);
}

void PocketGenerator::on_check_hlen_auto_tcp_stateChanged(int val)
{
	ui.line_hlen_tcp->setDisabled(val);
}

void PocketGenerator::on_check_csum_auto_tcp_stateChanged(int val)
{
	ui.line_csum_tcp->setDisabled(val);
}

void PocketGenerator::on_check_length_auto_udp_stateChanged(int val)
{
	ui.line_length_udp->setDisabled(val);
}

void PocketGenerator::on_check_csum_auto_udp_stateChanged(int val)
{
	ui.line_csum_udp->setDisabled(val);
}

void PocketGenerator::on_check_csum_auto_icmp_stateChanged(int val)
{
	ui.line_checksum_icmp->setDisabled(val);
}
#pragma endregion

void PocketGenerator::on_push_button_auto_val_clicked()
{
	PB.set_eth_header(&ethernet_header);
	PB.set_ip_header(&ip_header);
	switch (PB.prot)
	{
	default:
	case IPPROTO_IP:
		break;

	case IPPROTO_TCP:
		PB.set_tcp_header(&tcp_header);
		break;

	case IPPROTO_UDP:
		PB.set_udp_header(&udp_header);
		break;

	case IPPROTO_ICMP:
		PB.set_icmp_header(&icmp_header);
		break;
	}

	string& data = ui.data_box->toPlainText().toStdString();
	if (ui.check_hex_data->isChecked())
	{
		std::vector<BYTE> hex_data;

		char* pos = (char*)data.data();
		char* old_pos;

		while (*pos != '\0')
		{
			old_pos = pos;
			while (*pos != '\0' && *pos != ' ')
			{
				pos++;
			}

			while (*pos == ' ')
			{
				*pos = '\0';
				pos++;
			}

			hex_data.push_back(QString(old_pos).toUInt((bool*)nullptr, 16));
		}
		PB.set_data((char*)hex_data.data(), hex_data.size());
	}
	else
	{
		PB.set_data((char*)data.data(), data.length());
	}

	//ui.textEdit->append("on_push_button_auto_val_clicked");
	if (ui.check_proto_auto_ip->isChecked())
	{
		ip_header.proto = PB.prot;
		ui.line_protocol_ip->setText(QString::number(ip_header.proto));
	}
	if (ui.check_length_auto_ip->isChecked())
	{
		ip_header.length = htons(PB.packet_size - 14);
		ui.line_length_ip->setText(QString::number(htons(ip_header.length)));
	}
	if (ui.check_csum_auto_ip->isChecked())
	{
		ip_header.eval_csum();
		ui.line_checksum_ip->setText(QString::number(ip_header.csum));
	}
	if (ui.check_hlen_auto_tcp->isChecked())
	{
		tcp_header.hdr_len = 5;
		ui.line_hlen_tcp->setText(QString::number(tcp_header.hdr_len));
	}
	if (ui.check_csum_auto_tcp->isChecked())
	{
		tcp_header.eval_csum(&ip_header, PB.packet + 54, PB.packet_size - 54); 
		ui.line_csum_tcp->setText(QString::number(tcp_header.csum));
	}
	if (ui.check_length_auto_udp->isChecked())
	{
		udp_header.length = htons(PB.packet_size - 34);
		ui.line_length_udp->setText(QString::number(htons(udp_header.length)));
	}
	if (ui.check_csum_auto_udp->isChecked())
	{
		udp_header.eval_csum(&ip_header, PB.packet + 42, PB.packet_size - 42);
		ui.line_csum_udp->setText(QString::number(udp_header.csum));
	}
	if (ui.check_csum_auto_icmp->isChecked())
	{
		icmp_header.eval_csum(PB.packet + 42, PB.packet_size - 42);
		ui.line_checksum_icmp->setText(QString::number(icmp_header.csum));
	}
}