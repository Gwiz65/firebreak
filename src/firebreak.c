/****************************************************************************
 * firebreak.c                                                              *
 *                                                                          *
 * Copyright (C) 2017 Gwiz <gwiz65@gmail.com>                               *
 *                                                                          *
 * firebreak is free software: you can redistribute it and/or modify it     *
 * under the terms of the GNU General Public License as published by the    *
 * Free Software Foundation, either version 3 of the License, or            *
 * (at your option) any later version.                                      *
 *                                                                          *
 * firebreak is distributed in the hope that it will be useful, but         *
 * WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
 * See the GNU General Public License for more details.                     *
 *                                                                          *
 * You should have received a copy of the GNU General Public License along  *
 * with this program.  If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                          *
 ****************************************************************************/
#include "firebreak.h"
#include <gtk/gtk.h>

/****************************
 *        Defines           *
 ****************************/
#define CULLRATE		1000		// milliseconds 
#define REFRESHRATE		1000		// milliseconds 
#define DECAYTIME		20			// seconds
#define GREYTIME		18			// seconds
#define MAXCONNECTIONS  2048		// max number of connections in each list

/****************************
 *       Variables          *
 ****************************/
GtkWidget *MainWindow;
GtkWidget *Device_label;
GtkWidget *MAC_label;
//GtkWidget *DeviceInfo3;
GtkListStore *IPv4_List;
GtkListStore *IPv6_List;
gchar *workdir = NULL;
gchar *canaryname = NULL;
pid_t fbmon_pid;
FILE *fifofile;
gboolean getmsgkill = FALSE;
gchar *fifoName = NULL;
struct stat st = {0};
gboolean cullloopkill = FALSE;
gboolean refreshloopkill = FALSE;
struct fb_connectioninfo IPv4Connections[MAXCONNECTIONS];
struct fb_connectioninfo IPv6Connections[MAXCONNECTIONS];

/****************************************************************************
 *                                                                          *
 * Function: Rescan                                                         *
 *                                                                          *
 * Purpose :                                                                *
 *                                                                          *
 ****************************************************************************/
gboolean Rescan (void)
{
	FILE *canaryfile;

	// create canary file - delete this file to kill fbmon
	canaryfile = fopen(canaryname, "w");
	if (canaryfile != NULL)
	{
		fprintf (canaryfile, "fbmon running");
		fclose(canaryfile);
	}
	else
	{
		g_print("Unable to create canary file.\n");
		return FALSE;
	}
	// fork a child process
	fbmon_pid = fork ();
	if (fbmon_pid == 0)
	{
		// This is the child process.  Execute our monitor prog
		//g_print("Child process running now\n");
		if (execlp("fbmon", "fbmon", NULL) == -1)
			g_print("Unable to run fbmon program. Reinstall Firebreak.\n");
		_exit(EXIT_FAILURE);
	}
	else if (fbmon_pid < 0)
	{
		// The fork failed.  Report failure. 
		g_print("Fork failed.\n");
		return FALSE;
	}
	else
	{
		int status;
		pid_t result;

		// This is the parent process.
		//g_print("Parent process still running\n");
		sleep(1);
		result = waitpid(fbmon_pid, &status, WNOHANG);
		if (result == 0) 
		{
			// Child is alive
			//g_print("Child started. This is good.\n");
		} 
		else 
		{
			// Child exited
			g_print("Child not running. This sucks like an Electrolux\n");
			return FALSE;
		}
	}
	return FALSE; 	// run once
}

/****************************************************************************
 *                                                                          *
 * Function: on_button1_clicked                                             *
 *                                                                          *
 * Purpose :                                                                *
 *                                                                          *
 ****************************************************************************/
void on_button1_clicked (GtkButton *button, gpointer user_data)
{
	// set device labels   
	gtk_label_set_text (GTK_LABEL(MAC_label), "");
	gtk_label_set_text (GTK_LABEL(Device_label), "");
	//gtk_label_set_text (GTK_LABEL(DeviceInfo3), "");
	// delete canary file to kill fbmon
	if (stat(canaryname, &st) == 0) remove(canaryname);
	// call RunMonitor function 
	gdk_threads_add_timeout (500, (GSourceFunc) Rescan, NULL);
}

/****************************************************************************
 *                                                                          *
 * Function: Check_for_Process                                              *
 *                                                                          *
 * Purpose : See if firebreak is already running                            *
 *           returns true if already running, false otherwise               *
 *                                                                          *
 ****************************************************************************/
gboolean Check_for_Process(void)
{
	gboolean func_ret = FALSE;
	DIR *procdir;
	struct dirent *procdirent;
	gint numoffirebreaks = 0;

	procdir = opendir("/proc");
	if (procdir)
	{
		while ((procdirent = readdir(procdir)) != NULL)
		{
			uint32_t pidnum = 0;

			pidnum = atol(procdirent->d_name);
			if (pidnum > 0)
			{
				FILE *statusfile;
				char filestr[2048];
				gchar *line = NULL;
				size_t len = 0;
				int ctr;
				char progname[256]; // temp string to hold program name

				sprintf(filestr, "/proc/%u/status", pidnum);
				// make sure file exists
				if (!(stat (filestr, &st) == -1)) 
				{
					statusfile = fopen(filestr, "r");
					if (statusfile != NULL)
					{
						ctr = 0;
						// get first line - Name:	systemd-logind
						if (getline (&line, &len, statusfile) != -1)
						{
							// get process name
							while ((line[ctr] != '\0') &&
							       (line[ctr] != '\n')) ctr++;
							if (line[ctr] == '\0') ctr--;
							if (line[ctr] == '\n') ctr--;
							ctr = ctr - 4;
							if (ctr > 0) snprintf(progname, ctr, "%s", &line[6]);
							//check if firebreak exists
							if (!strncmp(progname, "firebreak", 9)) numoffirebreaks++;
						}
						fclose (statusfile);
					}
				}
				g_free(line);
			}
		}
		closedir(procdir);
	}
	if (numoffirebreaks > 1) func_ret = TRUE;
	return func_ret;
}

/****************************************************************************
 *                                                                          *
 * Function: GetMsg                                                         *
 *                                                                          *
 * Purpose :                                                                *
 *                                                                          *
 ****************************************************************************/
gboolean GetMsg (void)
{
	size_t read = 0;
	struct fb_message fbmessage;
	gboolean b_alreadyexists = FALSE;

	//g_print("GetMsg function called.\n");
	if (getmsgkill) return FALSE;
	read = fread (&fbmessage, sizeof(struct fb_message), 1, fifofile);
	if (read > 0)
	{
		int ctr;

		if (fbmessage.type == 0)
		{
			// we have a device message
			if (fbmessage.data_size == 0)
			{
				// no devices found
				// should probably kill threads here since nothing
				// will happen until rescanned
				gtk_label_set_text (GTK_LABEL(Device_label), "No devices found.");
			}
			else
			{

				// fill display info

				
				gchar *tempchar = NULL;

				// if port = 1 clear & fill top label1
				if (fbmessage.port == 1)
				{
					tempchar =  g_strdup_printf("%s", fbmessage.devname);
					gtk_label_set_text (GTK_LABEL(Device_label), tempchar);

					tempchar =  g_strdup_printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", 
					                            fbmessage.address[0],
					                            fbmessage.address[1],
					                            fbmessage.address[2],
					                            fbmessage.address[3],
					                            fbmessage.address[4],
					                            fbmessage.address[5]);
					gtk_label_set_text (GTK_LABEL(MAC_label), tempchar);

					
				}
				// if port > 2 append to label
				if (fbmessage.port > 1)
				{
					tempchar = g_strdup_printf("%s\n%s", 
					                           gtk_label_get_label(GTK_LABEL(Device_label)),
					                           fbmessage.devname);
					gtk_label_set_text (GTK_LABEL(Device_label), tempchar);

					tempchar = g_strdup_printf("%s\n%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", 
					                           gtk_label_get_label(GTK_LABEL(MAC_label)),
					                            fbmessage.address[0],
					                            fbmessage.address[1],
					                            fbmessage.address[2],
					                            fbmessage.address[3],
					                            fbmessage.address[4],
					                            fbmessage.address[5]);
					gtk_label_set_text (GTK_LABEL(MAC_label), tempchar);



				}
				g_free(tempchar);
		


			}
		}

		if ((fbmessage.type > 0) && (fbmessage.type < 5)) // ipv4
		{
			// see if connection already exists
			for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
			{
				b_alreadyexists = FALSE;
				if ((!memcmp(fbmessage.address, IPv4Connections[ctr].address, 16)) && 
				    (fbmessage.port == IPv4Connections[ctr].port))
					b_alreadyexists = TRUE;
				if ((fbmessage.type < 3) && (IPv4Connections[ctr].type == 2))
					b_alreadyexists = FALSE;
				if ((fbmessage.type > 2) && (IPv4Connections[ctr].type == 1))
					b_alreadyexists = FALSE;
				if (b_alreadyexists)
				{
					//g_print("Already exists\n");
					// add datasize to data totals
					if ((fbmessage.type == 1) || (fbmessage.type == 3))
						IPv4Connections[ctr].data_recd = 
						IPv4Connections[ctr].data_recd + fbmessage.data_size;
					else
						IPv4Connections[ctr].data_sent = 
						IPv4Connections[ctr].data_sent + fbmessage.data_size;
					// update lastseen
					IPv4Connections[ctr].lastseen = time(NULL);
					break;
				}
			}
			if (!b_alreadyexists)
			{
				int openslot;
				char progname[256]; // temp string to hold program name

				// find first open slot
				for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
				{
					if (IPv4Connections[ctr].type == 0)
					{
						openslot = ctr;
						break;
					}
					if (ctr == (MAXCONNECTIONS - 1)) openslot = 0;
				}
				//g_print("Slot #%i | ", openslot);
				// fill data
				if (fbmessage.type < 3) 
				{
					IPv4Connections[openslot].type = 1;
					//g_print("TCP | ");
				}
				else 
				{
					IPv4Connections[openslot].type = 2;
					//g_print("UDP | ");
				}
				// set devname
				sprintf(IPv4Connections[openslot].devname, "%s", fbmessage.devname);
				//g_print("%s | ", IPv4Connections[openslot].devname);

				if ((fbmessage.type == 1) || (fbmessage.type == 3))
				{
					IPv4Connections[openslot].data_recd = fbmessage.data_size;
					//g_print("%d recd | ", IPv4Connections[openslot].data_recd);
				}
				else
				{
					IPv4Connections[openslot].data_sent = fbmessage.data_size;
					//g_print("%d sent | ", IPv4Connections[openslot].data_sent);
				}
				// set pid
				IPv4Connections[openslot].pid = fbmessage.pid;
				//g_print("%i | ", IPv4Connections[openslot].pid);
				// get process name
				{
					FILE *statusfile;
					char filestr[2048];
					gchar *line = NULL;
					size_t len = 0;
					

					sprintf(progname, "%s", ""); //default
					// open /proc/$pid$/status file
					if (fbmessage.pid > 0)
					{
						sprintf(filestr, "/proc/%u/status", fbmessage.pid);
						// make sure file exists
						if (!(stat (filestr, &st) == -1)) 
						{
							statusfile = fopen(filestr, "r");
							if (statusfile != NULL)
							{
								ctr = 0;
								// get first line - Name:	systemd-logind
								if (getline (&line, &len, statusfile) != -1)
								{
									// get process name
									while ((line[ctr] != '\0') &&
									       (line[ctr] != '\n')) ctr++;
									if (line[ctr] == '\0') ctr--;
									if (line[ctr] == '\n') ctr--;
									ctr = ctr - 4;
									if (ctr > 0) snprintf(progname, ctr, "%s", &line[6]);
								}
								fclose (statusfile);
							}
						}
						g_free(line);
					}
				}
				// set progname
				sprintf(IPv4Connections[openslot].program, "%s", progname);
				//g_print("%s | ", IPv4Connections[openslot].program);
				// set address
				memcpy(&IPv4Connections[openslot].address[0], &fbmessage.address[0], 4);
				memset(&IPv4Connections[openslot].address[4], 0, 12);
				// set address string
				inet_ntop(AF_INET, &fbmessage.address, IPv4Connections[openslot].addressstring, INET_ADDRSTRLEN);
				//g_print("%s | ", IPv4Connections[openslot].addressstring);
				// set port
				IPv4Connections[openslot].port = fbmessage.port;
				//g_print("%i \n", IPv4Connections[openslot].port);
				// set firstseen
				IPv4Connections[openslot].firstseen = time(NULL);
				// set lastseen
				IPv4Connections[openslot].lastseen = IPv4Connections[openslot].firstseen;
			}
		}
		if ((fbmessage.type > 4) && (fbmessage.type < 9)) // ipv6
		{
			// see if connection already exists
			for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
			{
				b_alreadyexists = FALSE;
				if ((!memcmp(fbmessage.address, IPv6Connections[ctr].address, 16)) && 
				    (fbmessage.port == IPv6Connections[ctr].port))
					b_alreadyexists = TRUE;
				if ((fbmessage.type < 7) && (IPv6Connections[ctr].type == 2))
					b_alreadyexists = FALSE;
				if ((fbmessage.type > 6) && (IPv6Connections[ctr].type == 1))
					b_alreadyexists = FALSE;
				if (b_alreadyexists)
				{
					//g_print("Already exists\n");
					// add datasize to data totals
					if ((fbmessage.type == 5) || (fbmessage.type == 7))
						IPv6Connections[ctr].data_recd = 
						IPv6Connections[ctr].data_recd + fbmessage.data_size;
					else
						IPv6Connections[ctr].data_sent = 
						IPv6Connections[ctr].data_sent + fbmessage.data_size;
					// update lastseen
					IPv6Connections[ctr].lastseen = time(NULL);
					break;
				}
			}
			if (!b_alreadyexists)
			{
				int openslot;
				char progname[256]; // temp string to hold program name

				// find first open slot
				for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
				{
					if (IPv6Connections[ctr].type == 0)
					{
						openslot = ctr;
						break;
					}
					if (ctr == (MAXCONNECTIONS - 1)) openslot = 0;
				}
				//g_print("Slot #%i | ", openslot);
				// fill data
				if (fbmessage.type < 7) 
				{
					IPv6Connections[openslot].type = 1;
					//g_print("TCP | ");
				}
				else 
				{
					IPv6Connections[openslot].type = 2;
					//g_print("UDP | ");
				}
				// set devname
				sprintf(IPv6Connections[openslot].devname, "%s", fbmessage.devname);
				//g_print("%s | ", IPv6Connections[openslot].devname);

				if ((fbmessage.type == 5) || (fbmessage.type == 7))
				{
					IPv6Connections[openslot].data_recd = fbmessage.data_size;
					//g_print("%d recd | ", IPv6Connections[openslot].data_recd);
				}
				else
				{
					IPv6Connections[openslot].data_sent = fbmessage.data_size;
					//g_print("%d sent | ", IPv6Connections[openslot].data_sent);
				}
				// set pid
				IPv6Connections[openslot].pid = fbmessage.pid;
				//g_print("%i | ", IPv6Connections[openslot].pid);
				// get process name
				{
					FILE *statusfile;
					char filestr[2048];
					gchar *line = NULL;
					size_t len = 0;

					sprintf(progname, "%s", ""); //default
					// open /proc/$pid$/status file
					if (fbmessage.pid > 0)
					{
						sprintf(filestr, "/proc/%u/status", fbmessage.pid);
						// make sure file exists
						if (!(stat (filestr, &st) == -1)) 
						{
							statusfile = fopen(filestr, "r");
							if (statusfile != NULL)
							{
								ctr = 0;
								// get first line - Name:	systemd-logind
								if (getline (&line, &len, statusfile) != -1)
								{
									// get process name
									while ((line[ctr] != '\0') &&
									       (line[ctr] != '\n')) ctr++;
									if (line[ctr] == '\0') ctr--;
									if (line[ctr] == '\n') ctr--;
									ctr = ctr - 4;
									if (ctr > 0) snprintf(progname, ctr, "%s", &line[6]);
								}
								fclose (statusfile);
							}
						}
						g_free(line);
					}
				}
				// set progname
				sprintf(IPv6Connections[openslot].program, "%s", progname);
				//g_print("%s | ", IPv6Connections[openslot].program);
				// set address
				memcpy(&IPv6Connections[openslot].address[0], &fbmessage.address[0], 16);
				// set address string
				inet_ntop(AF_INET6, &fbmessage.address, IPv6Connections[openslot].addressstring, INET6_ADDRSTRLEN);
				//g_print("%s | ", IPv6Connections[openslot].addressstring);
				// set port
				IPv6Connections[openslot].port = fbmessage.port;
				//g_print("%i \n", IPv6Connections[openslot].port);
				// set firstseen
				IPv6Connections[openslot].firstseen = time(NULL);
				// set lastseen
				IPv6Connections[openslot].lastseen = IPv6Connections[openslot].firstseen;
			}
		}
	}
	return TRUE;  //keep runing
}
/******************************************************************************
 *                                                                            *
 * Function: CullConnectionList                                               *
 *                                                                            *
 * Purpose : Removes connections that have expired                            *
 *                                                                            *
 ******************************************************************************/
gboolean CullConnectionList(void)
{
	int ctr;

	if (cullloopkill) return FALSE;
	//g_print("CullConnectionList function called.\n");
	for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
	{
		if (difftime(time(NULL), IPv4Connections[ctr].lastseen) > DECAYTIME)
			// zero the connection
			memset(&IPv4Connections[ctr], 0, sizeof(struct fb_connectioninfo));		
		if (difftime(time(NULL), IPv6Connections[ctr].lastseen) > DECAYTIME)
			// zero the connection
			memset(&IPv6Connections[ctr], 0, sizeof(struct fb_connectioninfo));		
	}
	return TRUE;  //keep runing
}

/******************************************************************************
 *                                                                            *
 * Function: RefreshConnectionView                                            *
 *                                                                            *
 * Purpose : Updates the connection treeview                                  *
 *                                                                            *
 ******************************************************************************/
gboolean RefreshConnectionView(void)
{
	int ctr;
	int numofconns;
	struct fb_connectioninfo sortlist[MAXCONNECTIONS];

	if (refreshloopkill) return FALSE;
	//g_print("RefreshConnectionView function called.\n");

	// IPv4
	// clear list store
	gtk_list_store_clear (IPv4_List);
	// zero sortlist
	memset(sortlist, 0, sizeof(struct fb_connectioninfo) * MAXCONNECTIONS);
	// step through connection list and copy to sortlist
	numofconns = 0;
	for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
	{
		if (IPv4Connections[ctr].type != 0)
		{
			memcpy(&sortlist[numofconns], &IPv4Connections[ctr], sizeof(struct fb_connectioninfo));
			numofconns++;
		}
	}
	if (numofconns > 0)
	{
		int i;
		int j;
		GtkTreeIter iter;

		// sort sortlist using bubble sort
		for (i = 0; i < numofconns; i++)
		{
			for (j = i + 1; j < numofconns; j++)
			{
				if (difftime(sortlist[j].firstseen, sortlist[i].firstseen) < 0)
				{
					struct fb_connectioninfo temp;

					memcpy(&temp, &sortlist[i], sizeof(struct fb_connectioninfo));
					memcpy(&sortlist[i], &sortlist[j], sizeof(struct fb_connectioninfo));
					memcpy(&sortlist[j], &temp, sizeof(struct fb_connectioninfo));
				}
			}
		}
		// fill liststore
		for (i = 0; i < numofconns; i++)
		{
			gchar *sizetmp = NULL;
			char temppid[256];

			//append line to liststore
			gtk_list_store_append (IPv4_List, &iter);
			// fill data
			gtk_list_store_set (IPv4_List, &iter, 0, sortlist[i].devname, -1);
			gtk_list_store_set (IPv4_List, &iter, 1, sortlist[i].addressstring, -1);
			if (sortlist[i].type == 1)
				gtk_list_store_set (IPv4_List, &iter, 2, "TCP", -1);
			else
				gtk_list_store_set (IPv4_List, &iter, 2, "UDP", -1);

			if (sortlist[i].pid < 1) sprintf(temppid, "%s", "");
			else sprintf(temppid, "%i", sortlist[i].pid);
			gtk_list_store_set (IPv4_List, &iter, 3, temppid, -1);
			gtk_list_store_set (IPv4_List, &iter, 4, (gint64) sortlist[i].port, -1);
			gtk_list_store_set (IPv4_List, &iter, 5, sortlist[i].program, -1);
			sizetmp = g_format_size ((guint64) sortlist[i].data_recd);
			gtk_list_store_set (IPv4_List, &iter, 6, sizetmp, -1);
			sizetmp = g_format_size ((guint64) sortlist[i].data_sent);
			gtk_list_store_set (IPv4_List, &iter, 7, sizetmp, -1);
			if (difftime(time(NULL), sortlist[i].lastseen) < GREYTIME)
				gtk_list_store_set (IPv4_List, &iter, 8, FALSE, -1);
			else				
				gtk_list_store_set (IPv4_List, &iter, 8, TRUE, -1);
			g_free(sizetmp);
		}
	}

	// IPv6
	// clear list store
	gtk_list_store_clear (IPv6_List);
	// zero sortlist
	memset(sortlist, 0, sizeof(struct fb_connectioninfo) * MAXCONNECTIONS);
	// step through connection list and copy to sortlist
	numofconns = 0;
	for (ctr = 0; ctr < MAXCONNECTIONS; ctr++)
	{
		if (IPv6Connections[ctr].type != 0)
		{
			memcpy(&sortlist[numofconns], &IPv6Connections[ctr], sizeof(struct fb_connectioninfo));
			numofconns++;
		}
	}
	if (numofconns > 0)
	{
		int i;
		int j;
		GtkTreeIter iter;

		// sort sortlist using bubble sort
		for (i = 0; i < numofconns; i++)
		{
			for (j = i + 1; j < numofconns; j++)
			{
				if (difftime(sortlist[j].firstseen, sortlist[i].firstseen) < 0)
				{
					struct fb_connectioninfo temp;

					memcpy(&temp, &sortlist[i], sizeof(struct fb_connectioninfo));
					memcpy(&sortlist[i], &sortlist[j], sizeof(struct fb_connectioninfo));
					memcpy(&sortlist[j], &temp, sizeof(struct fb_connectioninfo));
				}
			}
		}
		// fill liststore
		for (i = 0; i < numofconns; i++)
		{
			gchar *sizetmp = NULL;
			char temppid[256];

			//append line to list store
			gtk_list_store_append (IPv6_List, &iter);
			// fill data
			gtk_list_store_set (IPv6_List, &iter, 0, sortlist[i].devname, -1);
			gtk_list_store_set (IPv6_List, &iter, 1, sortlist[i].addressstring, -1);
			if (sortlist[i].type == 1)
				gtk_list_store_set (IPv6_List, &iter, 2, "TCP", -1);
			else
				gtk_list_store_set (IPv6_List, &iter, 2, "UDP", -1);

			if (sortlist[i].pid < 1) sprintf(temppid, "%s", "");
			else sprintf(temppid, "%i", sortlist[i].pid);
			gtk_list_store_set (IPv6_List, &iter, 3, temppid, -1);
			gtk_list_store_set (IPv6_List, &iter, 4, (gint64) sortlist[i].port, -1);
			gtk_list_store_set (IPv6_List, &iter, 5, sortlist[i].program, -1);
			sizetmp = g_format_size ((guint64) sortlist[i].data_recd);
			gtk_list_store_set (IPv6_List, &iter, 6, sizetmp, -1);
			sizetmp = g_format_size ((guint64) sortlist[i].data_sent);
			gtk_list_store_set (IPv6_List, &iter, 7, sizetmp, -1);
			if (difftime(time(NULL), sortlist[i].lastseen) < GREYTIME)
				gtk_list_store_set (IPv6_List, &iter, 8, FALSE, -1);
			else				
				gtk_list_store_set (IPv6_List, &iter, 8, TRUE, -1);
			g_free(sizetmp);
		}
	}
	return TRUE;  //keep runing
}

/******************************************************************************
 *                                                                            *
 * Function: RunMonitor                                                       *
 *                                                                            *
 * Purpose :                                                                  *
 *                                                                            *
 ******************************************************************************/
gboolean RunMonitor (void)
{
	FILE *canaryfile;

	// create canary file - delete this file to kill fbmon
	canaryfile = fopen(canaryname, "w");
	if (canaryfile != NULL)
	{
		fprintf (canaryfile, "fbmon running");
		fclose(canaryfile);
	}
	else
	{
		g_print("Unable to create canary file.\n");
		return FALSE;
	}
	// set fifoName
	fifoName = g_strconcat (workdir, "/.fbmonfifo", NULL);	
	// create fifo
	mkfifo(fifoName, 0600);
	// fork a child process
	fbmon_pid = fork ();
	if (fbmon_pid == 0)
	{
		// This is the child process.  Execute our monitor prog
		//g_print("Child process running now\n");
		if (execlp("fbmon", "fbmon", NULL) == -1)
			g_print("Unable to run fbmon program. Reinstall Firebreak.\n");
		_exit(EXIT_FAILURE);
	}
	else if (fbmon_pid < 0)
	{
		// The fork failed.  Report failure. 
		g_print("Fork failed.\n");
		return FALSE;
	}
	else
	{
		int status;
		pid_t result;

		// This is the parent process.
		//g_print("Parent process still running\n");
		sleep(1);
		result = waitpid(fbmon_pid, &status, WNOHANG);
		if (result == 0) 
		{
			// Child is alive
			//g_print("Child started. This is good.\n");
			// open fifo for read 
			fifofile = fopen(fifoName,"r");
			if (fifofile != NULL)
			{
				//g_print("Fifo open for read by parent.\n");
				// call our GetMsg function 
				gdk_threads_add_timeout (1, (GSourceFunc) GetMsg, NULL);
			}
			else
			{
				g_print("Parent failed to open fifo.\n");
			}
		} 
		else 
		{
			// Child exited
			g_print("Child not running. This sucks like an Electrolux\n");
			return FALSE;
		}
	}
	return FALSE; 	// run once
}

/******************************************************************************
 *                                                                            *
 * Function: MainWindowDestroy                                                * 
 *                                                                            *
 * Purpose : called when the main window is closed                            *
 *                                                                            *
 ******************************************************************************/
void MainWindowDestroy (GtkWidget *widget, gpointer data)
{
	// delete canary file to kill fbmon
	if (stat(canaryname, &st) == 0) remove(canaryname);
	// kill threads
	getmsgkill = TRUE;
	cullloopkill = TRUE;
	refreshloopkill = TRUE;
	sleep(1);
	// close & delete fifo
	if (fifofile != NULL) fclose(fifofile);
	unlink(fifoName);
	// release our widgets
	gtk_widget_destroy (MainWindow);
	gtk_widget_destroy (Device_label);
	gtk_widget_destroy (MAC_label);
	//gtk_widget_destroy (DeviceInfo3);
	// kill main loop
	gtk_main_quit ();
}

/******************************************************************************
 *                                                                            *
 * Function: CreateMainWindow                                                 *
 *                                                                            *
 * Purpose : creates main window                                              *
 *                                                                            *
 ******************************************************************************/
static GtkWidget* CreateMainWindow (void)
{
	GtkWidget *window = NULL;
	GtkBuilder *builder;
	GError* error = NULL;

	// load UI from file
	builder = gtk_builder_new ();
	if (gtk_builder_add_from_file (builder, UI_FILE, &error))
	{
		// auto-connect signal handlers
		gtk_builder_connect_signals (builder, NULL);
		// get widgets we care about 
		window = GTK_WIDGET (gtk_builder_get_object (builder, "mainwindow"));
		Device_label = GTK_WIDGET (gtk_builder_get_object (builder, "label8"));
		MAC_label = GTK_WIDGET (gtk_builder_get_object (builder, "label9"));
		//DeviceInfo3 = GTK_WIDGET (gtk_builder_get_object (builder, "label6"));
		// list store objects
		IPv4_List = GTK_LIST_STORE (gtk_builder_get_object (builder,"liststore1"));
		IPv6_List = GTK_LIST_STORE (gtk_builder_get_object (builder,"liststore2"));
		// unload builder
		g_object_unref (builder);
	}
	else
		g_print ("Unable to load GTK builder file. Reinstall Firebreak.\n"); 
	// zero connection lists
	memset(IPv4Connections, 0, sizeof(struct fb_connectioninfo) * MAXCONNECTIONS);
	memset(IPv6Connections, 0, sizeof(struct fb_connectioninfo) * MAXCONNECTIONS);
	// clear device display
	gtk_label_set_text (GTK_LABEL(Device_label), "");
	gtk_label_set_text (GTK_LABEL(MAC_label), "");
	//gtk_label_set_text (GTK_LABEL(DeviceInfo3), "");
	
	return window;
}

/******************************************************************************
 *                                                                            *
 * Function: main                                                             *
 *                                                                            *
 * Purpose : program entry function                                           *
 *                                                                            *
 ******************************************************************************/
int main (int argc, char *argv[])
{
	// check if already running
	if (Check_for_Process())
	{
		g_print("Firebreak is already running.\n");
		exit(1);
	}
	// set our work directory
	workdir = g_strconcat (g_get_home_dir (), "/.firebreak", NULL);
	// make sure work directory exists

	if (stat (workdir, &st) == -1) mkdir (workdir, 0700);
	// temporarily use canaryname to deletfifo
	canaryname = g_strconcat (workdir, "/.fbmonfifo", NULL);	
	if (stat(canaryname, &st) == 0) remove(canaryname);
	// set canary name	
	canaryname = g_strconcat (workdir, "/.fbmonstat", NULL);	
	if (stat(canaryname, &st) == 0) remove(canaryname);
	// initialize gtk
	gtk_init (&argc, &argv);
	// create main window
	MainWindow = CreateMainWindow();
	if (MainWindow == NULL) return 1;
	// show main window
	gtk_widget_show (MainWindow);
	// call RunMonitor function as soon as we are idle
	gdk_threads_add_idle ((GSourceFunc)RunMonitor, NULL);
	// start the cull loop thread
	gdk_threads_add_timeout (CULLRATE, (GSourceFunc) CullConnectionList, NULL);
	// start the view update thread
	gdk_threads_add_timeout (REFRESHRATE, (GSourceFunc) RefreshConnectionView, NULL);
	// start main loop
	gtk_main ();
	return 0;
}
