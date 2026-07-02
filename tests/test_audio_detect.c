/*
 * Unit tests for the USB sysfs -> ALSA card correlation.
 *
 * Builds a synthetic sysfs tree under a mkdtemp directory:
 *
 *   devices/pci0/usb1/1-2/1-2:1.4/sound/card0         (modem's UAC card)
 *   devices/pci0/usb1/1-4/1-4.2/1-4.2:1.0/sound/card1 (other device, via hub)
 *   class/sound/cardN/device -> symlinks like real sysfs
 *
 * Run with `make check`.
 */

#include "../src/audio_detect.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, name) do { \
	if (cond) { \
		printf("ok   %s\n", name); \
	} else { \
		printf("FAIL %s\n", name); \
		failures++; \
	} \
} while (0)

static void mkdirs(const char *root, const char *rel)
{
	char path[PATH_MAX];
	char *p;

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	for (p = path + strlen(root) + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(path, 0755);
			*p = '/';
		}
	}
	mkdir(path, 0755);
}

static void make_card(const char *root, const char *usbdev, int card)
{
	char rel[PATH_MAX], link[PATH_MAX], target[PATH_MAX];

	/* devices/.../<usbdev>/sound/cardN + class/sound/cardN/device symlink */
	snprintf(rel, sizeof(rel), "%s/sound/card%d", usbdev, card);
	mkdirs(root, rel);

	snprintf(rel, sizeof(rel), "class/sound/card%d", card);
	mkdirs(root, rel);

	snprintf(link, sizeof(link), "%s/class/sound/card%d/device", root, card);
	snprintf(target, sizeof(target), "%s/%s", root, usbdev);
	symlink(target, link);
}

int main(void)
{
	char root[] = "/tmp/mm_audio_detect_XXXXXX";
	char token[64];
	char err[256];
	char modem[PATH_MAX];
	int card = -1;

	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return 1;
	}

	/* token extraction */
	CHECK(!mm_audio_usb_root_token("/sys/devices/pci0/usb1/1-2", token, sizeof(token))
		&& !strcmp(token, "1-2"), "token: plain device");
	CHECK(!mm_audio_usb_root_token("/sys/devices/pci0/usb1/1-2/1-2.3/1-2.3:1.0", token, sizeof(token))
		&& !strcmp(token, "1-2.3"), "token: behind hub, deepest wins, interface ignored");
	CHECK(mm_audio_usb_root_token("/sys/devices/pci0/0000:00:1f.3", token, sizeof(token)) == -1,
		"token: PCI-only path has none");
	CHECK(mm_audio_usb_root_token("/sys/devices/foo/1-2", token, sizeof(token)) == -1,
		"token: port-like component without usbN root is rejected");

	/* fixture: modem on usb1 port 2, its UAC interface owns card0 */
	make_card(root, "devices/pci0/usb1/1-2/1-2:1.4", 0);
	/* unrelated USB audio device behind a hub on port 4, owns card1 */
	make_card(root, "devices/pci0/usb1/1-4/1-4.2/1-4.2:1.0", 1);

	snprintf(modem, sizeof(modem), "%s/devices/pci0/usb1/1-2", root);
	CHECK(!mm_audio_card_for_physdev(root, modem, &card, err, sizeof(err)) && card == 0,
		"match: modem resolves to its own card");

	snprintf(modem, sizeof(modem), "%s/devices/pci0/usb1/1-4/1-4.2", root);
	CHECK(!mm_audio_card_for_physdev(root, modem, &card, err, sizeof(err)) && card == 1,
		"match: hub-attached device resolves to its card");

	snprintf(modem, sizeof(modem), "%s/devices/pci0/usb1/1-9", root);
	CHECK(mm_audio_card_for_physdev(root, modem, &card, err, sizeof(err)) == -1
		&& strstr(err, "no ALSA card"), "match: unknown device fails with diagnostic");

	/* ambiguity: second card on the same USB device */
	make_card(root, "devices/pci0/usb1/1-2/1-2:1.6", 2);
	snprintf(modem, sizeof(modem), "%s/devices/pci0/usb1/1-2", root);
	CHECK(mm_audio_card_for_physdev(root, modem, &card, err, sizeof(err)) == -1
		&& strstr(err, "ambiguous"), "match: two cards on one device is ambiguous");

	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
