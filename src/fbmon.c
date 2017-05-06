/******************************************************************************
 * fbmon.c                                                                *
 *                                                                            *
 * Copyright (C) 2016 Gwiz <gwiz65@gmail.com>                                 *
 *                                                                            *
 * firebreak is free software: you can redistribute it and/or modify it       *
 * under the terms of the GNU General Public License as published by the      *
 * Free Software Foundation, either version 3 of the License, or              *
 * (at your option) any later version.                                        *
 *                                                                            *
 * firebreak is distributed in the hope that it will be useful, but           *
 * WITHOUT ANY WARRANTY; without even the implied warranty of                 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                       *
 * See the GNU General Public License for more details.                       *
 *                                                                            *
 * You should have received a copy of the GNU General Public License along    *
 * with this program.  If not, see <http://www.gnu.org/licenses/>.            *
 *                                                                            *
 ******************************************************************************/
#include "firebreak.h"

/****************************
 *        Variables          *
 ****************************/
struct stat st = {0};

/****************************************************************************
 *                                                                          *
 * Function: GetPIDfromPort                                                 *
 *                                                                          *
 * Purpose :                                                                *
 *                                                                          *
 ****************************************************************************/
pid_t GetPIDfromPort(uint16_t port)
{
	FILE *portlist = NULL;

	// looping list of the last 16 ports we've seen to reduce searches
	static struct existing_ports Existing_Ports[16];
	static int nextopenslot = 0;
	static int usedslots = 0;
	int p;
	pid_t ret = 0;

	// see if port exists in our list and return saved pid
	for (p = 0; p < usedslots; p++)
	{
		if (Existing_Ports[p].port == port)
			ret = Existing_Ports[p].pid;
	}
	if (ret == 0)
	{
		// wasn't in our list
		for (p = 1; p < 5; p++)
		{
			if      (p == 1) portlist = fopen("/proc/net/tcp", "r");
			else if (p == 2) portlist = fopen("/proc/net/udp", "r");
			else if (p == 3) portlist = fopen("/proc/net/tcp6", "r");
			else if (p == 4) portlist = fopen("/proc/net/udp6", "r");
			if (portlist != NULL)
			{
				char *line;
				size_t len = 0;
				char port_str[10];

				snprintf(port_str, 10, "%.4X", port);
				while (getline(&line, &len, portlist) != -1) 
				{
					char gl_port[10];

					if      (p == 1) strncpy(gl_port, &line[15], 4);
					else if (p == 2) strncpy(gl_port, &line[16], 4);
					else if (p == 3) strncpy(gl_port, &line[39], 4);
					else if (p == 4) strncpy(gl_port, &line[40], 4);
					if (!strncmp(port_str, gl_port, 4)) 
					{
						uint32_t inode = 0;
						char temp[15];

						if      (p == 1) strncpy(temp, &line[91], 12);
						else if (p == 2) strncpy(temp, &line[92], 12);
						else if (p == 3) strncpy(temp, &line[139], 12);
						else if (p == 4) strncpy(temp, &line[140], 12);
						inode = atol(temp);
						if (inode > 0)
						{
							DIR *procdir;
							struct dirent *procdirent;

							procdir = opendir("/proc");
							if (procdir)
							{
								while ((procdirent = readdir(procdir)) != NULL)
								{
									uint32_t pidnum = 0;
									pidnum = atol(procdirent->d_name);

									if (pidnum > 0)
									{
										DIR *fddir;
										struct dirent *fddirent;
										char fdpath[PATH_MAX];

										sprintf(fdpath, "/proc/%d/fd/", pidnum);
										fddir = opendir(fdpath);
										if (fddir)
										{
											while ((fddirent = readdir(fddir)) != NULL)
											{
												char temppath[PATH_MAX];
												char readlinkbuf[1024];
												int len;

												sprintf(temppath, "/proc/%d/fd/%s", 
												        pidnum, fddirent->d_name);
												if ((len = readlink(temppath, readlinkbuf, sizeof(readlinkbuf)-1)) > 0)
												{
													char compstr[256];

													readlinkbuf[len] = '\0';
													sprintf(compstr, "socket:[%d]", inode);
													if (!strncmp(readlinkbuf, compstr, strlen(compstr)))
													{
														ret = pidnum;
														Existing_Ports[nextopenslot].port = port;
														Existing_Ports[nextopenslot].pid = pidnum;
														nextopenslot++; if (nextopenslot > 15) nextopenslot = 0;
														usedslots++; if (usedslots > 15) usedslots = 15;
													}
												}

											}
											closedir(fddir);
										}
									}
								}
								closedir(procdir);
							}
						}
					}
				}
				fclose(portlist);
			}
		}
	}
	return ret; 
}

/****************************************************************************
 *                                                                          *
 * Function: main                                                           *
 *                                                                          *
 * Purpose :                                                                *
 *                                                                          *
 ****************************************************************************/
int main(int argc, char *argv[])
{
	switch (argc) 
	{
		case 1:
		{

		// no args
		FILE *fifofile;
		char fifoName[PATH_MAX];
		DIR           *d;
		struct dirent *dir;
		struct dev_info DevInfo[MAXDEVICES];
		int numofdevices = 0;
		int saddr_size; 
		int data_size;
		struct sockaddr saddr;
		int sock_raw;
		unsigned char *buffer = (unsigned char *) malloc(65536); // big ass buffer
		int ctr;


		//printf("fbmon: Now running. Woo hoo!\n");
		// open and close fifo so gui won't block

		sprintf(fifoName, "%s%s", getenv ("HOME"),"/.firebreak/.fbmonfifo");
		//char *s = getenv ("HOME");


		fifofile = fopen(fifoName,"w");
		if (fifofile != NULL) fclose(fifofile);
		else
		{
			printf("fbmon: Failed first open fifo. Exiting...\n");
			return 1;
		}
		// scan for devices
		memset(DevInfo, 0, sizeof(struct dev_info) * MAXDEVICES);
		d = opendir("/sys/class/net");
		if (d)
		{
			while ((dir = readdir(d)) != NULL)
			{
				// ignore anything with "." and loopback device
				if (!((!strncmp(dir->d_name, ".", 1)) || (!strncmp(dir->d_name, "lo", 2))))
				{
					char buf[256];
					char tmppath[PATH_MAX];
					FILE *fp;
					uint8_t mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
					int i;

					sprintf(tmppath, "/sys/class/net/%s/address", dir->d_name);
					fp = fopen(tmppath, "rt");
					memset(buf, 0, 256);
					if (fp) {
						//printf("Here.\n");
						if (fgets(buf, sizeof buf, fp) > 0) {
							sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0],
							       &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
						}
						fclose(fp);
					}
					if (!((mac[0] == 0x00) && (mac[1] == 0x00) && (mac[2] == 0x00) &&
					      (mac[3] == 0x00) && (mac[4] == 0x00) && (mac[5] == 0x00)))
					{
						sprintf(DevInfo[numofdevices].name, dir->d_name);
						for (i = 0; i < 6; i++) DevInfo[numofdevices].mac[i] = mac[i];
						printf("%s\n", DevInfo[numofdevices].name);
						printf("Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", 
						       DevInfo[numofdevices].mac[0], DevInfo[numofdevices].mac[1], DevInfo[numofdevices].mac[2], 
						       DevInfo[numofdevices].mac[3], DevInfo[numofdevices].mac[4], DevInfo[numofdevices].mac[5]);
						numofdevices++;
					}
				}
			}
			closedir(d);
		}
		printf("Number of found devices = %i\n", numofdevices);
		if (numofdevices == 0) 
		{
			struct fb_message fbmessage;

			// no devices found - send message and quit
			memset(&fbmessage, 0, sizeof(struct fb_message));
			fbmessage.type = 0;
			fbmessage.data_size = 0;
			fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
			//close fifo
			fclose(fifofile);
			return 0;
		}

		// send device messages
		// type = 0
		// device = device name
		// data_size = numofdevices
		// first 6 of address = mac


		for (ctr = 0; ctr < numofdevices; ctr++)
		{
			// open fifo for write
			fifofile = fopen(fifoName,"w");
			if (fifofile != NULL)
			{
				struct fb_message fbmessage;

				memset(&fbmessage, 0, sizeof(struct fb_message));
				fbmessage.type = 0;
				sprintf(fbmessage.devname, "%s", DevInfo[ctr].name);
				memcpy(&fbmessage.address[0], &DevInfo[ctr].mac[0], 6);
				fbmessage.data_size = numofdevices;
				fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
				//close fifo
				fclose(fifofile);
			}
			else
			{
				printf("fbmon: Failed to open fifo.\n");
				return 1;
			}
		}

		// open a raw socket
		sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(sock_raw < 0)
		{
			printf("Socket error\n");
			return 1;
		}
		while (1) // loop forever
		{
			saddr_size = sizeof saddr;
			struct fb_message fbmessage;
			memset(&fbmessage, 0, sizeof(struct fb_message));

			//Receive a packet
			data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*) &saddr_size);
			if(data_size < 0 )
			{
				printf("Recvfrom error\n");
				return 1;
			}
			else
			{
				// Process the packet
				// open fifo for write
				fifofile = fopen(fifoName,"w");
				if (fifofile != NULL)
				{
					int xfervector = 0;	//0=?,1=in,2=out

					int msgdev = 0;
					int q;
					struct ethhdr *eth = (struct ethhdr *) buffer;

					// ignore anything not explicitly addressed to or from us
					for (q = 0; q < numofdevices; q++)
					{
						if ((DevInfo[q].mac[0] == eth->h_dest[0]) &&
						    (DevInfo[q].mac[1] == eth->h_dest[1]) &&
						    (DevInfo[q].mac[2] == eth->h_dest[2]) &&
						    (DevInfo[q].mac[3] == eth->h_dest[3]) &&
						    (DevInfo[q].mac[4] == eth->h_dest[4]) &&
						    (DevInfo[q].mac[5] == eth->h_dest[5])) 
						{
							msgdev = q;
							xfervector = 1;
						}
						if ((DevInfo[q].mac[0] == eth->h_source[0]) &&
						    (DevInfo[q].mac[1] == eth->h_source[1]) &&
						    (DevInfo[q].mac[2] == eth->h_source[2]) &&
						    (DevInfo[q].mac[3] == eth->h_source[3]) &&
						    (DevInfo[q].mac[4] == eth->h_source[4]) &&
						    (DevInfo[q].mac[5] == eth->h_source[5])) 
						{
							msgdev = q;
							xfervector = 2;
						}
					}
					// ignore broadcast messages
					if ((eth->h_dest[0] == 0x00) &&
					    (eth->h_dest[1] == 0x00) &&
					    (eth->h_dest[2] == 0x00) &&
					    (eth->h_dest[3] == 0x00) &&
					    (eth->h_dest[4] == 0x00) &&
					    (eth->h_dest[0] == 0x00)) xfervector = 0;
					if ((eth->h_dest[0] == 0xFF) &&
					    (eth->h_dest[1] == 0xFF) &&
					    (eth->h_dest[2] == 0xFF) &&
					    (eth->h_dest[3] == 0xFF) &&
					    (eth->h_dest[4] == 0xFF) &&
					    (eth->h_dest[0] == 0xFF)) xfervector = 0;
					// ignore IPv4 Multicast address
					if ((eth->h_dest[0] == 0x01) &&
					    (eth->h_dest[1] == 0x00) &&
					    (eth->h_dest[2] == 0x5E)) xfervector = 0;
					// ignore IPv6 Multicast address
					if ((eth->h_dest[0] == 0x33) &&
					    (eth->h_dest[1] == 0x33)) xfervector = 0;
					if (xfervector)
					{
						// only process ipv4 & ipv6 messages
						if (ntohs(eth->h_proto) == ETH_P_IP)
						{
							// IPv4 protocol
							struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr)); /* Point to the IP header */ 

							char sourceipstr[INET_ADDRSTRLEN];
							char destipstr[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &iph->saddr, sourceipstr, INET_ADDRSTRLEN);
							inet_ntop(AF_INET, &iph->daddr, destipstr, INET_ADDRSTRLEN);

							if (iph->protocol == 0x06) // TCP
							{
								// point to tcp header
								struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));  

								if (xfervector == 1)
								{
									//fprintf(fifofile, " [ RECV ][ PID: %5d ][ Port: %5d ][ IPv4 ][ %4d bytes ][ TCP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(tcph->dest)), ntohs(tcph->dest), 
									//        data_size, ntohs(tcph->source), sourceipstr);
									fbmessage.type = 1;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(tcph->dest));
									//fbmessage.locport = ntohs(tcph->dest);
									fbmessage.port = ntohs(tcph->source);
									memcpy(&fbmessage.address[0], &iph->saddr, 4);
									memset(&fbmessage.address[4], 0, 12);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
								else
								{
									//fprintf(fifofile, " [ SENT ][ PID: %5d ][ Port: %5d ][ IPv4 ][ %4d bytes ][ TCP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(tcph->source)), ntohs(tcph->source), 
									//        data_size, ntohs(tcph->dest), destipstr);
									fbmessage.type = 2;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(tcph->source));
									//fbmessage.locport = ntohs(tcph->source);
									fbmessage.port = ntohs(tcph->dest);
									memcpy(&fbmessage.address[0], &iph->daddr, 4);
									memset(&fbmessage.address[4], 0, 12);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
							}
							if (iph->protocol == 0x11) // UDP
							{
								// point to udp header
								struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));  

								if (xfervector == 1)
								{
									//fprintf(fifofile, " [ RECV ][ PID: %5d ][ Port: %5d ][ IPv4 ][ %4d bytes ][ UDP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(udph->dest)), ntohs(udph->dest), 
									//        data_size, ntohs(udph->source), sourceipstr);
									fbmessage.type = 3;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(udph->dest));
									//fbmessage.locport = ntohs(udph->dest);
									fbmessage.port = ntohs(udph->source);
									memcpy(&fbmessage.address[0], &iph->saddr, 4);
									memset(&fbmessage.address[4], 0, 12);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
								else
								{
									//fprintf(fifofile, " [ SENT ][ PID: %5d ][ Port: %5d ][ IPv4 ][ %4d bytes ][ UDP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(udph->source)), ntohs(udph->source), 
									//        data_size, ntohs(udph->dest), destipstr);
									fbmessage.type = 4;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(udph->source));
									//fbmessage.locport = ntohs(udph->source);
									fbmessage.port = ntohs(udph->dest);
									memcpy(&fbmessage.address[0], &iph->daddr, 4);
									memset(&fbmessage.address[4], 0, 12);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
							}
						}
						else if (ntohs(eth->h_proto) == ETH_P_IPV6) 
						{
							// IPv6 protocol
							struct ip6_hdr *ip6h = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

							char sourceip6str[INET6_ADDRSTRLEN];
							char destip6str[INET6_ADDRSTRLEN];
							inet_ntop(AF_INET6, &ip6h->ip6_src, sourceip6str, INET6_ADDRSTRLEN);
							inet_ntop(AF_INET6, &ip6h->ip6_dst, destip6str, INET6_ADDRSTRLEN);

							// ** to do ** - need routine to handle next header chains

							if (ip6h->ip6_nxt == 0x06) // TCP
							{
								// point to tcp header
								struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));  

								if (xfervector == 1)
								{
									//fprintf(fifofile, " [ RECV ][ PID: %5d ][ Port: %5d ][ IPv6 ][ %4d bytes ][ TCP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(tcph->dest)), ntohs(tcph->dest), 
									//        data_size, ntohs(tcph->source), sourceip6str);
									fbmessage.type = 5;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(tcph->dest));
									//fbmessage.locport = ntohs(tcph->dest);
									fbmessage.port = ntohs(tcph->source);
									memcpy(&fbmessage.address[0], &ip6h->ip6_src, 16);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
								else
								{
									//fprintf(fifofile, " [ SENT ][ PID: %5d ][ Port: %5d ][ IPv6 ][ %4d bytes ][ TCP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(tcph->source)), ntohs(tcph->source), 
									//        data_size, ntohs(tcph->dest), destip6str);
									fbmessage.type = 6;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(tcph->source));
									//fbmessage.locport = ntohs(tcph->source);
									fbmessage.port = ntohs(tcph->dest);
									memcpy(&fbmessage.address[0], &ip6h->ip6_dst, 16);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
							}
							if (ip6h->ip6_nxt == 0x11) // UDP
							{
								// point to udp header
								struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));  

								if (xfervector == 1)
								{
									//fprintf(fifofile, " [ RECV ][ PID: %5d ][ Port: %5d ][ IPv6 ][ %4d bytes ][ UDP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(udph->dest)), ntohs(udph->dest), 
									//        data_size, ntohs(udph->source), sourceip6str);
									fbmessage.type = 7;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(udph->dest));
									//fbmessage.locport = ntohs(udph->dest);
									fbmessage.port = ntohs(udph->source);
									memcpy(&fbmessage.address[0], &ip6h->ip6_src, 16);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
								else
								{
									//fprintf(fifofile, " [ SENT ][ PID: %5d ][ Port: %5d ][ IPv6 ][ %4d bytes ][ UDP ][ Port: %5d ][ IP: %s ]\n",
									//        GetPIDfromPort(ntohs(udph->source)), ntohs(udph->source), 
									//        data_size, ntohs(udph->dest), destip6str);
									fbmessage.type = 8;
									sprintf(fbmessage.devname, "%s", DevInfo[msgdev].name);
									// memcpy(&fbmessage.devmac[0], &DevInfo[msgdev].mac[0], 6);
									fbmessage.data_size = data_size;
									fbmessage.pid = GetPIDfromPort(ntohs(udph->source));
									//fbmessage.locport = ntohs(udph->source);
									fbmessage.port = ntohs(udph->dest);
									memcpy(&fbmessage.address[0], &ip6h->ip6_dst, 16);
									fwrite (&fbmessage, sizeof(struct fb_message), 1, fifofile);
								}
							}
						}
					}
					//close fifo
					fclose(fifofile);
				}
				else
				{
					printf("fbmon: Failed to open fifo.\n");
					return 1;
				}
			}
		}
		close(sock_raw);
		break;
	}
		default:
		{
			printf("fbmon: Incorrect number of arguments. Exiting...\n");
			return 1;
		}
	}
	return 0;
}
