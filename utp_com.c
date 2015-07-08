/* utp_com tool is used to send commands to hardware via Freescale's UTP protocol.
 * Copyright (C) 2015 Ixonos Plc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef WIN32
#include <windows.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <strsafe.h>
#include <intsafe.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>

#include "getopt.h"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

#define CLOSE CloseHandle
#define FILE_HANDLE HANDLE
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg_lib.h>
#include <scsi/sg_io_linux.h>

#define CLOSE close
#define FILE_HANDLE int
#endif

#define BUSY_SLEEP           500
#define BUSY_CHECK_COUNT     500
#define CMD_TIMEOUT          (5 * 60 * 1000)
#define UTP_CMD_SIZE         0x10
#define UTP_REPLY_BYTE       13
#define SENSE_BUF_SIZE       16
#define FILE_SIZE_OFFSET     10
#define MAX_SENT_DATA_SIZE   0x10000

// UTP reply codes
#define UTP_REPLY_PASS 0
#define UTP_REPLY_EXIT 1
#define UTP_REPLY_BUSY 2
#define UTP_REPLY_SIZE 3

int extra_info = 0;
#ifdef WIN32
#pragma pack (push , 1)
struct utp_cmd
{
	uint8_t data[UTP_CMD_SIZE];
};
#else
struct __attribute__ (( packed ))utp_cmd
{
	uint8_t data[UTP_CMD_SIZE];
};
#endif


struct utp_cmd poll =
{0xf0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct utp_cmd exec =
{
	0xf0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

struct utp_cmd put =
{
	0xf0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

void print_help()
{
	printf("Usage: 'upt_com -d device -c command [-f file] [-e]'\n");
	printf("\t-d\tdevice\n");
	printf("\t-c\tcommand to be run\n");
	printf("\t-f\tfile to be set\n");
	printf("\t-e\textra info prints\n");
	printf("\n\te.g. sudo ./upt_com -d /dev/sdb -c \"$ uname -r\"\n");
}

int send_cmd(FILE_HANDLE device_fd, struct utp_cmd *cmd, void *dxferp, int dxferp_len, uint8_t *utp_reply_code)
{
	int err = 1;
	int ret;
	uint8_t sensebuf[SENSE_BUF_SIZE] = {0};

	// Create sg io header
#ifdef WIN32
	int junk;
	int totalBufferLength = sizeof(SCSI_PASS_THROUGH) + SENSE_BUF_SIZE + dxferp_len;
	SCSI_PASS_THROUGH *hdr = (SCSI_PASS_THROUGH*) malloc(totalBufferLength);

	hdr->Length = sizeof(SCSI_PASS_THROUGH);
	hdr->SenseInfoLength = SENSE_BUF_SIZE;
	hdr->DataTransferLength = dxferp_len;

	hdr->SenseInfoOffset = sizeof(SCSI_PASS_THROUGH);
	hdr->DataBufferOffset = sizeof(SCSI_PASS_THROUGH) + SENSE_BUF_SIZE;

	memset(hdr->SenseInfoOffset + (char*)hdr, 0, hdr->SenseInfoLength);
	memcpy(hdr->DataBufferOffset + (char*)hdr, dxferp, hdr->DataTransferLength);
		
	hdr->PathId = 0;
	hdr->TargetId = 1;
	hdr->Lun = 0;
	hdr->CdbLength = UTP_CMD_SIZE;
	memcpy(hdr->Cdb, (unsigned char *)cmd->data, UTP_CMD_SIZE);
	hdr->DataIn = SCSI_IOCTL_DATA_OUT;
	hdr->TimeOutValue = CMD_TIMEOUT;
#else
	struct sg_io_hdr sgio_hdr;
	memset(&sgio_hdr, 0, sizeof(sgio_hdr));
	sgio_hdr.sbp = sensebuf;
	sgio_hdr.interface_id = 'S';
	sgio_hdr.timeout = CMD_TIMEOUT;
	sgio_hdr.cmd_len = UTP_CMD_SIZE;
	sgio_hdr.cmdp = (unsigned char *)cmd->data;
	sgio_hdr.mx_sb_len = SENSE_BUF_SIZE;
	sgio_hdr.dxfer_direction = SG_DXFER_TO_DEV;
	sgio_hdr.dxfer_len = dxferp_len;
	sgio_hdr.dxferp = dxferp;
#endif

	// Print CDB data
	if (extra_info)
	{
		int i;
		for (i = 0; i < UTP_CMD_SIZE; i++)
		{
#ifdef WIN32
			printf("Sent data %02d: 0x%02x\n", i, hdr->Cdb[i]);
#else
			printf("Sent data %02d: 0x%02x\n", i, sgio_hdr.cmdp[i]);
#endif
		}
	}

	// Call IOCTL
#ifdef WIN32
	ret = DeviceIoControl(device_fd, IOCTL_SCSI_PASS_THROUGH, hdr, totalBufferLength, NULL, 0, &junk, NULL);
#else
	ret = ioctl(device_fd, SG_IO, &sgio_hdr);
#endif
	if (ret < 0)
	{
		fprintf(stderr, "SG_IO ioctl error\n");
		CLOSE(device_fd);
		goto cleanup;
	}

	// Print sense data
	if (extra_info)
	{
		int i;
		for (i = 0; i < SENSE_BUF_SIZE; i++)
		{
			uint8_t sense_data = sensebuf[i];

			if (sense_data != 0)
			{
				printf("Sense data %02d: 0x%02x\n", i, sense_data);
			}
		}
	}

	if (utp_reply_code)
	{
		*utp_reply_code = sensebuf[UTP_REPLY_BYTE];
	}

	if (sensebuf[UTP_REPLY_BYTE] == UTP_REPLY_EXIT)
	{
		fprintf(stderr, "UTP_REPLY_EXIT\n");
		CLOSE(device_fd);
		goto cleanup;
	}

	err = 0;
cleanup:
#ifdef WIN32
	free(hdr);
#endif
	return err;
}

int main(int argc, char * argv[])
{
	int c;
	int ret;
	FILE_HANDLE file_fd;
	FILE_HANDLE device_fd;
	struct stat st;
	char *command = NULL;
	char *file_name = NULL;
	char *file_data = NULL;
	char *device_name = NULL;
	int data_read;
	int total_read = 0;
	struct utp_cmd put_send;
	int data_written;
	int i;
	uint8_t reply;

	opterr = 0;

	// Parse parameters
	while ((c = getopt(argc, argv, "c:d:ef:")) != -1)
	{
		switch (c)
		{
			case 'c':
				command = optarg;
				break;
			case 'd':
				device_name = optarg;
				break;
			case 'e':
				extra_info = 1;
				break;
			case 'f':
				file_name = optarg;
				break;
			default:
				print_help();
				return 1;
		}
	}

	// Check that we got device name
	if (!device_name)
	{
		print_help();
		return 1;
	}

	// Check did we got file name
	if (file_name)
	{
		// Get file size
		if (stat(file_name, &st) != 0)
		{
			fprintf(stderr, "Error reading file size: %s\n", file_name);
			return 1;
		}

		// Allocate memory
		file_data = (char*)malloc(st.st_size);

		// Open file
#ifdef WIN32
		file_fd = CreateFile(file_name, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
#else
		file_fd = open(file_name, O_RDONLY);
#endif
		if (file_fd < 0)
		{
			fprintf(stderr, "Error opening file: %s\n", file_name);
			return 1;
		}

		// Read data
		do {
#ifdef WIN32
			ReadFile(file_fd, file_data + total_read, st.st_size - total_read, &data_read, 0);
#else
			data_read = read(file_fd, file_data + total_read, st.st_size - total_read);
#endif
			if (data_read == 0)
				break;

			if (extra_info)
			{
				printf("Read from file: %d bytes\n", data_read);
			}

			total_read += data_read;
		} while (1);

		CLOSE(file_fd);

		// Check that the whole file was read
		if (total_read != st.st_size)
		{
			fprintf(stderr, "Not all data was read from file. Size %d Read %d\n", (int)st.st_size, total_read);
			return 1;
		}
	}

	// Open device
#ifdef WIN32
	device_fd = CreateFile(device_name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (device_fd == (FILE_HANDLE)-1)
#else
	device_fd = open(device_name, O_RDWR);
	if (device_fd < 0)
#endif
	{
		fprintf(stderr, "Error opening device: %s\n", device_name);
		return 1;
	}

	// If sending file
	if (file_name)
	{
		// Send "Send" in exec command with file size. Bytes 6 - 13 (64bit)
		struct utp_cmd exec_send;
		memcpy(&exec_send, &exec, sizeof(exec_send));
		memcpy(exec_send.data + FILE_SIZE_OFFSET, &st.st_size, sizeof(uint32_t));

		ret = send_cmd(device_fd, &exec_send, command, strlen(command), NULL);
		if (ret)
		{
			fprintf(stderr, "Send_cmd failed (exec_send)\n");
		}

		// Send data in put command
		memcpy(&put_send, &put, sizeof(put_send));

		data_written = 0;
		while (data_written < st.st_size)
		{
			int write_size = st.st_size - data_written > MAX_SENT_DATA_SIZE ? MAX_SENT_DATA_SIZE : st.st_size - data_written;

			ret = send_cmd(device_fd, &put_send, file_data + data_written, write_size, NULL);
			if (ret)
			{
				fprintf(stderr, "Send_cmd failed (put_send)\n");
				break;
			}

			data_written += write_size;
		}
	}
	else
	{
		// Call exec command
		ret = send_cmd(device_fd, &exec, command, strlen(command), NULL);
		if (ret)
		{
			fprintf(stderr, "Send_cmd failed (exec)\n");
		}

		// Wait until not busy
		reply = UTP_REPLY_BUSY;
		for (i = 0; i < BUSY_CHECK_COUNT; i++)
		{
#ifdef WIN32
			Sleep(BUSY_SLEEP);
#else
			sleep(BUSY_SLEEP);
#endif

			ret = send_cmd(device_fd, &poll, "", 0, &reply);
			if (ret)
			{
				fprintf(stderr, "Send_cmd failed (poll)\n");
				break;
			}

			if (reply == 0)
			{
				break;
			}

			if (i == BUSY_CHECK_COUNT - 1)
			{
				fprintf(stderr, "Device is busy\n");
				ret = 1;
				break;
			}
		}
	}

	CLOSE(device_fd);

	return ret;
}
