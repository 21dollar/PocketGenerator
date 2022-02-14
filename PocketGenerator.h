#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <QtWidgets/QMainWindow>
#include "ui_PocketGenerator.h"

#include <winsock2.h>
#include <pcap.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

#define QSUM(a)  (((a) & 0xffff) + (((a) >> 16) & 0xffff))
typedef struct ethernet_layer{
	BYTE dst_mac[6];
	BYTE src_mac[6];
	WORD type;

	QString src_mac_toQstring()
	{
		QString macStr;

		if ((uint)src_mac[0] < 0x10u) macStr += '0';
		macStr += QString::number(src_mac[0], 16);

		for (int i = 1; i < 6; i++)
		{
			macStr += ':';
			if ((uint)src_mac[i] < 0x10u) macStr += '0';
			macStr += QString::number(src_mac[i], 16);
		}

		return macStr;
	}
	QString dst_mac_toQstring()
	{
		QString macStr;

		if ((uint)dst_mac[0] < 0x10u) macStr += '0';
		macStr += QString::number(dst_mac[0], 16);

		for (int i = 1; i < 6; i++)
		{
			macStr += ':';
			if ((uint)dst_mac[i] < 0x10u) macStr += '0';
			macStr += QString::number(dst_mac[i], 16);
		}

		return macStr;
	}

	void clear()
	{
		memset(this, 0, 14);
	}

}ETH_HEADER, * PETH_HEADER;

typedef struct ip_layer
{
	BYTE hdr_len : 4;
	BYTE version : 4;
	BYTE tos;
	WORD length;
	WORD id;

	BYTE frag_offset_h : 5;
	BYTE more_frag : 1;
	BYTE dont_frag : 1;
	BYTE reserved : 1;

	BYTE frag_offset_l;
	
	BYTE ttl;
	BYTE proto;
	WORD csum;
	DWORD src_addr;
	DWORD dst_addr;

	void eval_csum()
	{
		csum = 0;
		WORD* sh_phdr = (WORD*)this;
		DWORD dw_csum = 0;

		for (int i = 0; i < 20 / 2; i++)
		{
			dw_csum += sh_phdr[i];
		}

		csum = ~QSUM(dw_csum);
	}

	void clear()
	{
		memset(this, 0, 20);
	}

}IP_HEADER, * PIP_HEADER;

typedef struct udp_layer
{
	WORD src_port;
	WORD dst_port;
	WORD length;
	WORD csum;

	void eval_csum(ip_layer* iphdr, BYTE* data, WORD data_len)
	{
		csum = 0;
		data[data_len] = '\0';
		WORD* sh_data = (WORD*)data;
		WORD* sh_phdr = (WORD*)this;
		WORD sh_data_len = (data_len + 1) / 2;

		DWORD dw_csum = QSUM(iphdr->src_addr) + QSUM(iphdr->dst_addr) + iphdr->proto + data_len;

		for (int i = 0; i < 8 / 2; i++)
		{
			dw_csum += sh_phdr[i];
		}

		for (int i = 0; i < sh_data_len; i++)
		{
			dw_csum += sh_data[i];
		}

		csum = ~QSUM(dw_csum);
	}

	void clear()
	{
		memset(this, 0, 8);
	}

}UDP_HEADER, * PUDP_HEADER;

typedef struct tcp_layer
{
	WORD src_port;
	WORD dst_port;
	DWORD seq;
	DWORD ack_knowledge;

	BYTE ns : 1;
	BYTE reserved : 3;
	BYTE hdr_len : 4;

	BYTE fin : 1;
	BYTE syn : 1;
	BYTE rst : 1;
	BYTE psh : 1;
	BYTE ack : 1;
	BYTE urg : 1;
	BYTE ecn : 1;
	BYTE cwr : 1;

	WORD window;
	WORD csum;
	WORD urg_ptr;

	void eval_csum(ip_layer* iphdr, BYTE* data, WORD data_len)
	{
		csum = 0;
		data[data_len] = '\0';
		WORD* sh_data = (WORD*)data;
		WORD* sh_phdr = (WORD*)this;
		WORD sh_data_len = (data_len + 1) / 2;

		DWORD dw_csum = QSUM(iphdr->src_addr) + QSUM(iphdr->dst_addr) + iphdr->proto + data_len;

		for (int i = 0; i < 20 / 2; i++)
		{
			dw_csum += sh_phdr[i];
		}

		for (int i = 0; i < sh_data_len; i++)
		{
			dw_csum += sh_data[i];
		}

		csum = ~QSUM(dw_csum);
	}

	void clear()
	{
		memset(this, 0, 20);
	}

}TCP_HEADER, * PTCP_HEADER;

typedef struct icmp_layer
{
	BYTE type;
	BYTE code;
	WORD csum;
	WORD id;
	WORD seq;

	void eval_csum(BYTE* data, WORD data_len)
	{
		csum = 0;
		data[data_len] = '\0';
		WORD* sh_data = (WORD*)data;
		WORD* sh_phdr = (WORD*)this;
		WORD sh_data_len = (data_len + 1) / 2;

		DWORD dw_csum = 0;

		for (int i = 0; i < 8 / 2; i++)
		{
			dw_csum += sh_phdr[i];
		}

		for (int i = 0; i < sh_data_len; i++)
		{
			dw_csum += sh_data[i];
		}

		csum = (~QSUM(dw_csum));
	}

	void clear()
	{
		memset(this, 0, 8);
	}

}ICMP_HEADER, * PICMP_HEADER;

class packet_builder
{
public:
	int prot;
	uchar packet[65636];
	int packet_size;

	packet_builder()
	{
		packet_size = 0;
		prot = IPPROTO_IP;
	}

	void set_eth_header(ethernet_layer* ethernet_header)
	{
		memcpy(packet, ethernet_header, 14);
		packet_size = 14;
	}

	void set_ip_header(ip_layer* ip_header)
	{
		memcpy(packet + 14, ip_header, 20);
		packet_size = 34;
	}

	void set_icmp_header(icmp_layer* icmp_header)
	{
		memcpy(packet + 34, icmp_header, 8);
		packet_size = 42;
	}

	void set_tcp_header(tcp_layer* tcp_header)
	{
		memcpy(packet + 34, tcp_header, 20);
		packet_size = 54;
	}

	void set_udp_header(udp_layer* udp_header)
	{
		memcpy(packet + 34, udp_header, 8);
		packet_size = 42;
	}

	void set_data(char* data, int dataSize)
	{
		switch (prot)
		{
		default:
		case IPPROTO_IP:
			memcpy(packet + 34, data, dataSize);
			packet_size = 34 + dataSize;
			break;

		case IPPROTO_TCP:
			memcpy(packet + 54, data, dataSize);
			packet_size = 54 + dataSize;
			break;

		case IPPROTO_UDP:
			memcpy(packet + 42, data, dataSize);
			packet_size = 42 + dataSize;
			break;

		case IPPROTO_ICMP:
			memcpy(packet + 42, data, dataSize);
			packet_size = 42 + dataSize;
			break;
		}
	}

private:
	
};

class PocketGenerator : public QMainWindow
{
	Q_OBJECT

public:
	PocketGenerator(QWidget *parent = Q_NULLPTR);

	void all_interface();

private slots:
	void on_push_button_auto_val_clicked();
	void on_button_clear_seq_clicked();
	void on_check_proto_auto_ip_stateChanged(int val);
	void on_check_length_auto_ip_stateChanged(int val);
	void on_check_csum_auto_ip_stateChanged(int val);
	void on_check_hlen_auto_tcp_stateChanged(int val);
	void on_check_csum_auto_tcp_stateChanged(int val);
	void on_check_length_auto_udp_stateChanged(int val);
	void on_check_csum_auto_udp_stateChanged(int val);
	void on_check_csum_auto_icmp_stateChanged(int val);

	void on_select_interface_currentIndexChanged(int index);
	void on_push_button_packet_clicked();
	void on_send_seq_button_packet_clicked();
	void on_tabWidget_currentChanged(int index);
	//IP
	void on_line_src_ip_editingFinished();
	void on_line_dst_ip_editingFinished();
	void on_line_version_ip_editingFinished();
	void on_line_hlen_ip_editingFinished();
	void on_line_tos_ip_editingFinished();
	void on_line_length_ip_editingFinished();
	void on_line_id_ip_editingFinished();
	void on_line_ttl_ip_editingFinished();
	void on_line_protocol_ip_editingFinished();
	void on_line_offset_ip_editingFinished();
	void on_line_checksum_ip_editingFinished();
	void on_check_zero_ip_stateChanged(int val);
	void on_check_df_ip_stateChanged(int val);
	void on_check_mf_ip_stateChanged(int val);
	//ICMP
	void on_line_type_icmp_editingFinished();
	void on_line_code_icmp_editingFinished();
	void on_line_id_icmp_editingFinished();
	void on_line_checksum_icmp_editingFinished();
	void on_line_seq_icmp_editingFinished();
	//TCP
	void on_line_src_tcp_editingFinished();
	void on_line_dst_tcp_editingFinished();
	void on_line_seq_num_tcp_editingFinished();
	void on_line_ack_num_tcp_editingFinished();
	void on_line_hlen_tcp_editingFinished();
	void on_line_win_tcp_editingFinished();
	void on_line_csum_tcp_editingFinished();
	void on_line_upoint_tcp_editingFinished();
	void on_check_ns_tcp_stateChanged(int val);
	void on_check_cwr_tcp_stateChanged(int val);
	void on_check_ece_tcp_stateChanged(int val);
	void on_check_urg_tcp_stateChanged(int val);
	void on_check_ack_tcp_stateChanged(int val);
	void on_check_psh_tcp_stateChanged(int val);
	void on_check_rst_tcp_stateChanged(int val);
	void on_check_syn_tcp_stateChanged(int val);
	void on_check_fin_tcp_stateChanged(int val);
	//UDP
	void on_line_src_udp_editingFinished();
	void on_line_dst_udp_editingFinished();
	void on_line_length_udp_editingFinished();
	void on_line_csum_udp_editingFinished();

private:
	Ui::PocketGeneratorClass ui;
	packet_builder PB;
	ethernet_layer ethernet_header;
	ip_layer ip_header;
	tcp_layer tcp_header;
	udp_layer udp_header;
	icmp_layer icmp_header;
	pcap_t* pcap_interface;
};


