/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <zephyr.h>
#include <nrf9160.h>

#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/lte_lc.h>
#include <modem/modem_info.h>
#include <modem/modem_key_mgmt.h>
#include <modem/nrf_modem_lib.h>
#include <modem/pdn.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <logging/log.h>

#include <drivers/gpio.h>
#include <power/reboot.h>

#include <device.h>
#include <drivers/i2c.h>
#define TSL25721_I2C_ADDR 0x39
#define SCD40_I2C_ADDR 0x62

#include "cmd.h"
#include "cmd_ascii.h"
#include "fota/fota_http.h"
#include "sipf/sipf_client_http.h"
#include "sipf/sipf_auth.h"
#include "gnss/gnss.h"
#include "uart_broker.h"

#include "registers.h"
#include "version.h"

LOG_MODULE_REGISTER(sipf, CONFIG_SIPF_LOG_LEVEL);

/** peripheral **/
#define LOOPTIME_MS (60000) //ループ60秒

#define LED_PORT DT_GPIO_LABEL(DT_ALIAS(led1), gpios)

#define LED1_PIN (DT_GPIO_PIN(DT_ALIAS(led1), gpios))
#define LED1_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led1), gpios))
#define LED2_PIN (DT_GPIO_PIN(DT_ALIAS(led2), gpios))
#define LED2_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led2), gpios))
#define LED3_PIN (DT_GPIO_PIN(DT_ALIAS(led3), gpios))
#define LED3_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led3), gpios))

#define SW1_PIN (DT_GPIO_PIN(DT_ALIAS(led4), gpios))
#define SW1_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led4), gpios))
#define SW2_PIN (DT_GPIO_PIN(DT_ALIAS(led5), gpios))
#define SW2_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led5), gpios))
#define SW3_PIN (DT_GPIO_PIN(DT_ALIAS(led6), gpios))
#define SW3_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led6), gpios))
#define SW4_PIN (DT_GPIO_PIN(DT_ALIAS(led7), gpios))
#define SW4_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led7), gpios))
#define SW5_PIN (DT_GPIO_PIN(DT_ALIAS(led8), gpios))
#define SW5_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led8), gpios))
#define SW6_PIN (DT_GPIO_PIN(DT_ALIAS(led9), gpios))
#define SW6_FLAGS (GPIO_OUTPUT_ACTIVE | DT_GPIO_FLAGS(DT_ALIAS(led9), gpios))


/**********/

/** TLS **/
#define TLS_SEC_TAG 42
static const char cert[] = {
#include "sipf/cert/sipf.iot.sakura.ad.jp"
};
BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");
/*********/

static K_SEM_DEFINE(lte_connected, 0, 1);
static const struct device *uart_dev;

/* Auth info */
#define SZ_USER_NAME (255)
#define SZ_PASSWORD (255)
static char user_name[SZ_USER_NAME];
static char password[SZ_PASSWORD];

/* Initialize AT communications */
int at_comms_init(void)
{
    int err;

    err = at_cmd_init();
    if (err) {
        LOG_ERR("Failed to initialize AT commands, err %d", err);
        return err;
    }

    err = at_notif_init();
    if (err) {
        LOG_ERR("Failed to initialize AT notifications, err %d", err);
        return err;
    }

    return 0;
}

/** LED **/
static int gpio_init(void)
{
    const struct device *dev;

    dev = device_get_binding(LED_PORT);
    if (dev == 0) {
        LOG_ERR("Nordic nRF GPIO driver was not found!");
        return 1;
    }
    int ret;
    /* Initialize LED1  */
    ret = gpio_pin_configure(dev, LED1_PIN, LED1_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", LED1_PIN, ret);
    ret = gpio_pin_set(dev, LED1_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", LED1_PIN, ret);

    /* Initialize LED2  */
    ret = gpio_pin_configure(dev, LED2_PIN, LED2_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", LED2_PIN, ret);
    ret = gpio_pin_set(dev, LED2_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", LED2_PIN, ret);

    /* Initialize LED3  */
    ret = gpio_pin_configure(dev, LED3_PIN, LED3_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", LED3_PIN, ret);
    ret = gpio_pin_set(dev, LED3_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", LED3_PIN, ret);

    /* Initialize SW1  */
    ret = gpio_pin_configure(dev, SW1_PIN, SW1_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW1_PIN, ret);
    ret = gpio_pin_set(dev, SW1_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW1_PIN, ret);

    /* Initialize SW2  */
    ret = gpio_pin_configure(dev, SW2_PIN, SW2_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW2_PIN, ret);
    ret = gpio_pin_set(dev, SW2_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW2_PIN, ret);

    /* Initialize SW3  */
    ret = gpio_pin_configure(dev, SW3_PIN, SW3_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW3_PIN, ret);
    ret = gpio_pin_set(dev, SW3_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW3_PIN, ret);

    /* Initialize SW4  */
    ret = gpio_pin_configure(dev, SW4_PIN, SW4_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW4_PIN, ret);
    ret = gpio_pin_set(dev, SW4_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW4_PIN, ret);

    /* Initialize SW5  */
    ret = gpio_pin_configure(dev, SW5_PIN, SW5_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW5_PIN, ret);
    ret = gpio_pin_set(dev, SW5_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW5_PIN, ret);

    /* Initialize SW6  */
    ret = gpio_pin_configure(dev, SW6_PIN, SW6_FLAGS);
    LOG_DBG("gpio_pin_configure(%d): %d", SW6_PIN, ret);
    ret = gpio_pin_set(dev, SW6_PIN, 0);
    LOG_DBG("gpio_pin_set(%d): %d", SW6_PIN, ret);

    return 0;
}

static int gpio_on(gpio_pin_t pin)
{
    const struct device *dev = device_get_binding(LED_PORT);
    if (dev == 0) {
        LOG_ERR("Nordic nRF GPIO driver was not found!");
        return 1;
    }
    gpio_pin_set(dev, pin, 1);
    return 0;
}

static int gpio_off(gpio_pin_t pin)
{
    const struct device *dev = device_get_binding(LED_PORT);
    if (dev == 0) {
        LOG_ERR("Nordic nRF GPIO driver was not found!");
        return 1;
    }
    gpio_pin_set(dev, pin, 0);
    return 0;
}

static int led1_toggle(void)
{
    const struct device *dev;
    static int val = 0;

    dev = device_get_binding(LED_PORT);
    if (dev == 0) {
        LOG_ERR("Nordic nRF GPIO driver was not found!");
        return 1;
    }
    gpio_pin_set(dev, LED1_PIN, val);
    val = (val == 0) ? 1 : 0;
    return 0;
}
/***********/

/** MODEM **/
#define REGISTER_TIMEOUT_MS (120000)
#define REGISTER_TRY (3)

static int cert_provision(void)
{
    int err;
    bool exists;
    uint8_t unused;

    err = modem_key_mgmt_exists(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, &exists, &unused);
    if (err) {
        LOG_ERR("Failed to check for certificates err %d", err);
        return err;
    }

    if (exists) {
        /* For the sake of simplicity we delete what is provisioned
         * with our security tag and reprovision our certificate.
         */
        err = modem_key_mgmt_delete(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
        if (err) {
            LOG_ERR("Failed to delete existing certificate, err %d", err);
        }
    }

    LOG_DBG("Provisioning certificate");

    /*  Provision certificate to the modem */
    err = modem_key_mgmt_write(TLS_SEC_TAG, MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, cert, sizeof(cert) - 1);
    if (err) {
        LOG_ERR("Failed to provision certificate, err %d", err);
        return err;
    }

    return 0;
}

static void lte_handler(const struct lte_lc_evt *const evt)
{
    LOG_DBG("evt->type=%d", evt->type);
    switch (evt->type) {
    case LTE_LC_EVT_NW_REG_STATUS:
        LOG_DBG("- evt->nw_reg_status=%d\n", evt->nw_reg_status);
        if (evt->nw_reg_status == LTE_LC_NW_REG_SEARCHING) {
            UartBrokerPrint("SEARCHING\r\n");
            break;
        }
        if ((evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME) || (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING)) {
            UartBrokerPrint("REGISTERD\r\n");
            k_sem_give(&lte_connected);
            break;
        }
        break;
    case LTE_LC_EVT_CELL_UPDATE:
        LOG_DBG("- mcc=%d, mnc=%d", evt->cell.mcc, evt->cell.mnc);
        break;
    case LTE_LC_EVT_LTE_MODE_UPDATE:
        LOG_DBG("- evt->lte_mode=%d", evt->lte_mode);
        break;
    case LTE_LC_EVT_MODEM_EVENT:
        LOG_DBG("- evt->modem_evt=%d", evt->modem_evt);
        break;
    default:
        break;
    }
}

static int init_modem_and_lte(void)
{
    static char at_ret[128];
    int err = 0;

    err = nrf_modem_lib_init(NORMAL_MODE);
    if (err) {
        LOG_ERR("Failed to initialize modem library!");
        return err;
    }

    /* Initialize AT comms in order to provision the certificate */
    err = at_comms_init();
    if (err) {
        LOG_ERR("Faild to at_comms_init(): %d", err);
        return err;
    }

    /* Provision certificates before connecting to the LTE network */
    err = cert_provision();
    if (err) {
        LOG_ERR("Faild to cert_provision(): %d", err);
        return err;
    }

    err = lte_lc_system_mode_set(LTE_LC_SYSTEM_MODE_LTEM_GPS, LTE_LC_SYSTEM_MODE_PREFER_AUTO);
    if (err) {
        LOG_ERR("Failed to System Mode set.");
        return err;
    }
    LOG_DBG("Setting system mode OK");

    err = at_cmd_write("AT\%XMAGPIO=1,0,0,1,1,1574,1577", NULL, 0, NULL);
    if (err != 0) {
        LOG_ERR("Failed to set XMAGPIO, err %d", err);
        return err;
    }
    LOG_DBG("Configure MAGPIO OK");

    err = at_cmd_write("AT\%XCOEX0=1,1,1565,1586", NULL, 0, NULL);
    if (err != 0) {
        LOG_ERR("Failed to set XCOEX0, err %d", err);
        return err;
    }
    LOG_DBG("Configure pin OK");

    /* PDN */
    uint8_t cid;
    err = pdn_init();
    if (err != 0) {
        LOG_ERR("Failed to pdn_init()");
        return err;
    }
    err = pdn_ctx_create(&cid, NULL);
    if (err != 0) {
        LOG_ERR("Failed to pdn_ctx_create(), err %d", err);
        return err;
    }
    // set APN
    err = pdn_ctx_configure(cid, "sakura", PDN_FAM_IPV4, NULL);
    if (err != 0) {
        LOG_ERR("Failed to pdn_ctx_configure(), err %d", err);
        return err;
    }
    LOG_DBG("Setting APN OK");

    /* CONNECT */
    enum at_cmd_state at_state;
    for (int i = 0; i < REGISTER_TRY; i++) {
        LOG_DBG("Initialize LTE");
        err = lte_lc_init();
        if (err) {
            LOG_ERR("Failed to initializes the modem, err %d", err);
            return err;
        }
        LOG_DBG("Initialize LTE OK");

        lte_lc_modem_events_enable();

        LOG_INF("[%d] Trying to attach to LTE network (TIMEOUT: %d ms)", i, REGISTER_TIMEOUT_MS);
        UartBrokerPrint("Trying to attach to LTE network (TIMEOUT: %d ms)\r\n", REGISTER_TIMEOUT_MS);
        err = lte_lc_connect_async(lte_handler);
        if (err) {
            LOG_ERR("Failed to attatch to the LTE network, err %d", err);
            return err;
        }
        err = k_sem_take(&lte_connected, K_MSEC(REGISTER_TIMEOUT_MS));
        if (err == -EAGAIN) {
            UartBrokerPrint("TIMEOUT\r\n");
            lte_lc_offline();
            lte_lc_deinit();
            continue;
        } else if (err == 0) {
            // connected

            // PSMの設定
            err = lte_lc_psm_req(true);
            if (err) {
                LOG_ERR("PSM request failed, error: %d", err);
            } else {
                LOG_DBG("PSM is enabled");
            }

            // ICCIDの取得
            err = at_cmd_write("AT%XICCID", at_ret, sizeof(at_ret), &at_state);
            if (err) {
                LOG_ERR("Failed to get ICCID, err %d", err);
                return err;
            }
            if (at_state == AT_CMD_OK) {
                char *iccid_top = &at_ret[9]; // ICCIDの先頭
                for (int i = 0; i < 20; i++) {
                    if (iccid_top[i] == 'F') {
                        iccid_top[i] = 0x00;
                    }
                }
                UartBrokerPrint("ICCID: %s\r\n", iccid_top);
            }
            return 0;
        } else {
            //
            return err;
        }
    }

    LOG_ERR("Faild to attach to LTE Network");
    return -1;
}

//I2Cのライト関数(デバイスドライバ, データ, 長さ, スレーブアドレス)
static int write_bytes(const struct device *i2c_dev, uint8_t *data, uint32_t num_bytes, uint8_t slave_addr)
{
	struct i2c_msg msgs;

	//ライトデータセット
	msgs.buf = data;
	msgs.len = num_bytes;
	msgs.flags = I2C_MSG_WRITE | I2C_MSG_STOP;

	//I2Cライト実行
	return i2c_transfer(i2c_dev, &msgs, 1, slave_addr);
}

//I2Cの読み込み関数(デバイスドライバ, 先頭アドレス(8bit), データ, 長さ, スレーブアドレス)
static int read_bytes(const struct device *i2c_dev, uint8_t addr, uint8_t *data, uint32_t num_bytes, uint8_t slave_addr)
{
	uint8_t wr_addr[2];
	struct i2c_msg msgs[2];

	//リードアドレスセット
	wr_addr[0] = addr;
	wr_addr[1] = addr;
	msgs[0].buf = wr_addr;
	msgs[0].len = 1U;
	msgs[0].flags = I2C_MSG_WRITE | I2C_MSG_RESTART;

	//リードデータセット
	msgs[1].buf = data;
	msgs[1].len = num_bytes;
	msgs[1].flags = I2C_MSG_READ | I2C_MSG_STOP;

	//I2Cリード実行
	return i2c_transfer(i2c_dev, &msgs[0], 2, slave_addr);
}

//I2Cの読み込み関数(デバイスドライバ, 先頭アドレス(16bit), データ, 長さ, スレーブアドレス)
static int read_bytes_add16(const struct device *i2c_dev, uint16_t addr, uint8_t *data, uint32_t num_bytes, uint8_t slave_addr)
{
	uint8_t wr_addr[2];
	struct i2c_msg msgs[2];

	//リードアドレスセット
	wr_addr[0] = (addr >> 8) & 0xFF;
	wr_addr[1] = addr & 0xFF;
	msgs[0].buf = wr_addr;
	msgs[0].len = 2U;
	msgs[0].flags = I2C_MSG_WRITE;

	//リードデータセット
	msgs[1].buf = data;
	msgs[1].len = num_bytes;
	msgs[1].flags = I2C_MSG_RESTART | I2C_MSG_READ | I2C_MSG_STOP;

	//I2Cリード実行
	return i2c_transfer(i2c_dev, &msgs[0], 2, slave_addr);
}

void main(void)
{
    int err;
    int64_t ms_now, ms_timeout;
	int i;

	// I2C関連
	const struct device *i2c_dev;
	const char* const i2cName = "I2C_2";
	uint8_t I2C_BUFF[32]; //I2Cデータバッファ
	int co2;                               //CO2センサー(SCD40)CO2濃度
	union { float f; int i; } temperature; //CO2センサー(SCD40)温度
	union { float f; int i; } humidity;    //CO2センサー(SCD40)湿度
	union { float f; int i; } luminance;   //環境光センサー輝度

	// 受信データ
	uint8_t TX_BUFF[1024];//送信データバッファ
	uint8_t RX_BUFF[1024];//受信データバッファ
	char *RX_PTR;         //受信文字列ポインタ
	char STR_BUFF[140];   //受信文字列バッファ
	char OTID[33];        //オブジェクト転送単位ID(16進表記 32桁)
	char USERTIME[17];    //USER SEND DATATIME(16進表記 16桁)
	char SIPFTIME[17];    //SIPF RECEIVE DATATIME(16進表記 16桁)
	char REMAINS[3];      //REMAIN(16進表記 2桁)
	char OBJQTYD[3];      //OBJECT_QTY(16進表記 2桁)
	char *OBJ_PTR;        //オブジェクトデータポインタ
	char OBJ_DATA[128];   //OBJECT_DATA
	char OBJ_ID[8][3];    //オブジェクト タグID (16進数 2桁)
	char OBJ_TYPE[8][3];  //オブジェクト Type (16進数 2桁)
	char OBJ_LEN[8][3];   //オブジェクト Length (16進数 2桁)
	char OBJ_VAL[8][9];   //オブジェクト Value (16進数 文字列)

    // 対ユーザーMUCのレジスタ初期化
    RegistersReset();

    // UartBrokerの初期化(以降、Debug系の出力も可能)
    uart_dev = device_get_binding(UART_LABEL);
	if (!uart_dev) {
		UartBrokerPrint("UART: Device driver not found.\n");
	}
    UartBrokerInit(uart_dev);
    UartBrokerPrint("*** non SIPF Client(Type%02X) v.%d.%d.%d ***\r\n", *REG_CMN_FW_TYPE, *REG_CMN_VER_MJR, *REG_CMN_VER_MNR, *REG_CMN_VER_REL);
#ifdef CONFIG_LTE_LOCK_PLMN
    UartBrokerPuts("* PLMN: " CONFIG_LTE_LOCK_PLMN_STRING "\r\n");
#endif
#ifdef CONFIG_SIPF_AUTH_DISABLE_SSL
    UartBrokerPuts("* Disable SSL, AUTH endpoint.\r\n");
#endif
#ifdef CONFIG_SIPF_CONNECTOR_DISABLE_SSL
    UartBrokerPuts("* Disable SSL, CONNECTOR endpoint.\r\n");
#endif
    // GPIOの初期化
    gpio_init();
    gpio_off(LED2_PIN);
    gpio_off(LED1_PIN);
    gpio_on(SW1_PIN);
    gpio_on(SW2_PIN);
    gpio_on(SW3_PIN);
    gpio_on(SW4_PIN);
    gpio_on(SW5_PIN);
    gpio_on(SW6_PIN);

    //モデムの初期化&LTE接続
    err = init_modem_and_lte();
    if (err) {
        gpio_off(LED2_PIN);
        gpio_off(LED1_PIN);
        return;
    }

    // GNSSの初期化
    if (gnss_init() != 0) {
        UartBrokerPuts("Failed to initialize GNSS peripheral\r\n");
    }

	// I2Cの初期化
	i2c_dev = device_get_binding(i2cName);
	if (i2c_dev == NULL) {
		UartBrokerPrint("I2C: Device driver not found.\r\n");
	}

	//環境光センサーの初期化
	UartBrokerPrint("TSL25721 init\r\n");
	I2C_BUFF[0] = 0x80|0x20|0x0F;
	I2C_BUFF[1] = 0x02;
	write_bytes(i2c_dev, I2C_BUFF, 2, TSL25721_I2C_ADDR);
	
	I2C_BUFF[0] = 0x80|0x20|0x01;
	I2C_BUFF[1] = 0xF6;
	write_bytes(i2c_dev, I2C_BUFF, 2, TSL25721_I2C_ADDR);

	I2C_BUFF[0] = 0x80|0x20|0x00;
	I2C_BUFF[1] = 0x02|0x01;
	write_bytes(i2c_dev, I2C_BUFF, 2, TSL25721_I2C_ADDR);

	//CO2センサー(SCD40)の初期化
	//SCD40 stop_periodic_measurement
	UartBrokerPrint("SCD40 stop_periodic_measurement \r\n");
	I2C_BUFF[0] = 0x3F;
	I2C_BUFF[1] = 0x86;
	write_bytes(i2c_dev, I2C_BUFF, 2, SCD40_I2C_ADDR);
	k_sleep(K_SECONDS(1));

	//SCD40 シリアルナンバー取得
	UartBrokerPrint("SCD40 get_serial_number \r\n");
	for (i = 0; i < sizeof(I2C_BUFF); i++) {
		I2C_BUFF[i] = 0x00;
	}
	read_bytes_add16(i2c_dev, 0x3682, I2C_BUFF, 9, SCD40_I2C_ADDR);
	for (i = 0; i < 9; i++) {
		UartBrokerPrint("SCD40 Read address 0x%02X. I2C_BUFF 0x%02X. \r\n", i,I2C_BUFF[i]);
	}
	k_sleep(K_SECONDS(1));

	//SCD40 計測開始 start_periodic_measurement
	UartBrokerPrint("SCD40 start_periodic_measurement \r\n");
	I2C_BUFF[0] = 0x21;
	I2C_BUFF[1] = 0xB1;
	write_bytes(i2c_dev, I2C_BUFF, 2, SCD40_I2C_ADDR);

    // LTEつながるならOKなFWよね
    boot_write_img_confirmed();

    // 認証モードをSIM認証にする
    uint8_t b, prev_auth_mode = 0x01;
    *REG_00_MODE = 0x01;

    for (;;) {
        err = SipfAuthRequest(user_name, sizeof(user_name), password, sizeof(user_name));
        LOG_DBG("SipfAuthRequest(): %d", err);
        if (err < 0) {
            // IPアドレス認証に失敗した
            UartBrokerPuts("Set AuthMode to `SIM Auth' faild...(Retry after 10s)\r\n");
            *REG_00_MODE = 0x00; // モードが切り替えられなかった
            k_sleep(K_MSEC(10000));
            continue;
        }
        break;
    }
    err = SipfClientHttpSetAuthInfo(user_name, password);
    if (err < 0) {
        // 認証情報の設定に失敗した
        *REG_00_MODE = 0x00; // モードが切り替えられなかった
    }

    UartBrokerPuts("+++ Ready +++\r\n");
    gpio_on(LED3_PIN);

	/*********************************************/
	/**********ここからLTEデータ通信開始**********/
	/*********************************************/

    ms_timeout = k_uptime_get() + LOOPTIME_MS;
    for (;;) {
		//UARTコマンド待受
		while (UartBrokerGetByte(&b) == 0)
		{
			CmdResponse *cr = CmdParse(b);
			if (cr != NULL) {
				// UARTにレスポンスを返す
				UartBrokerPut(cr->response, cr->response_len);
			}
		}

		//ここから先周期的なデータ通信
		ms_now = k_uptime_get();
		if ((ms_timeout - ms_now) < 0) {
			ms_timeout = ms_now + LOOPTIME_MS;
			led1_toggle();

			read_bytes_add16(i2c_dev, 0xE4B8, I2C_BUFF, 3, SCD40_I2C_ADDR); //CO2センサーステータスリード
			if (I2C_BUFF[1] != 0x00) //CO2センサーが計測完了していたら数値読み込み
			{
				//CO2センサーの値を取得
				read_bytes_add16(i2c_dev, 0xEC05, I2C_BUFF, 9, SCD40_I2C_ADDR); //SCD40 read_measurement
				co2 = (I2C_BUFF[0] << 8) + I2C_BUFF[1]; //CO2の値
				temperature.f = ((I2C_BUFF[3] << 8) + I2C_BUFF[4]) * 175.0 / 65535.0 - 45.0; //温度の値
				humidity.f = ((I2C_BUFF[6] << 8) + I2C_BUFF[7]) * 100.0 / 65535.0; //湿度の値

				//環境光センサーの値を取得
				read_bytes(i2c_dev, 0x80|0x20|0x14, I2C_BUFF, 2, TSL25721_I2C_ADDR);
				luminance.f = (I2C_BUFF[1] << 8 | I2C_BUFF[0]) / 19.0; //環境光の値

				//センサーの値をUARTに表示
				UartBrokerPrint("SCD40 CO2  %08X %dppm \r\n", co2, co2);
				UartBrokerPrint("SCD40 Temp %08X %.2fC\r\n", temperature.i, temperature.f);
				UartBrokerPrint("SCD40 Humi %08X %.2f%%\r\n", humidity.i, humidity.f);
				UartBrokerPrint("TSL25721   %08X %.2fuW/cm2\r\n", luminance.i, luminance.f);
				
				//LTE通信でオブジェクトデータを送信する
				sprintf(TX_BUFF, "$TX 01 04 %08X 02 08 %08X 03 08 %08X 04 08 %08X",
				                 co2,temperature.i,humidity.i,luminance.i); //送信コマンドとデータをバッファにセット
				CmdAsciiParse(TX_BUFF, strlen(TX_BUFF), RX_BUFF, sizeof(RX_BUFF)); //コマンド実行

				//LTE通信でオブジェクトデータ受信する
				sprintf(TX_BUFF, "$RX"); //RXコマンドをバッファにセット
				CmdAsciiParse(TX_BUFF, strlen(TX_BUFF), RX_BUFF, sizeof(RX_BUFF)); //コマンド実行
				for (i = 0; i < 140; i++)
				{
					STR_BUFF[i] = (char)RX_BUFF[i];
				}
				STR_BUFF[138] = '\r';
				STR_BUFF[139] = '\n';
				UartBrokerPrint("RX DATA =>\r\n");
				UartBrokerPrint("%s",STR_BUFF); //受信データをUARTに表示

				//受信データ分離開始
				RX_PTR = strtok(STR_BUFF, "\r\n");
				if (RX_PTR != NULL)
				{
					sprintf(OTID, "%s", RX_PTR); //オブジェクト転送単位ID(16進表記 32桁)
					UartBrokerPrint("OTID->%s\r\n",OTID);
				}

				//OTIDが"OK"から始まった場合は処理終了
				if (OTID[0] == 'O' && OTID[1] == 'K')
				{
					UartBrokerPrint("RX EMPTY\r\n"); //受信データがありません
				}
				else
				{
					//ヘッダーデータ分離
					if (RX_PTR != NULL)
					{
						RX_PTR = strtok(NULL, "\r\n");
						sprintf(USERTIME, "%s", RX_PTR); //USER SEND DATATIME(16進表記 16桁)
						UartBrokerPrint("USERTIME->%s\r\n",USERTIME);
					}
					if (RX_PTR != NULL)
					{
						RX_PTR = strtok(NULL, "\r\n");
						sprintf(SIPFTIME, "%s", RX_PTR); //SIPF RECEIVE DATATIME(16進表記 16桁)
						UartBrokerPrint("SIPFTIME->%s\r\n",SIPFTIME);
					}
					if (RX_PTR != NULL)
					{
						RX_PTR = strtok(NULL, "\r\n");
						sprintf(REMAINS, "%s", RX_PTR); //REMAIN(16進表記 2桁)
						UartBrokerPrint("REMAINS->%s\r\n",REMAINS);
					}
					if (RX_PTR != NULL)
					{
						RX_PTR = strtok(NULL, "\r\n");
						sprintf(OBJQTYD, "%s", RX_PTR); //OBJECT_QTY(16進表記 2桁)
						UartBrokerPrint("OBJQTYD->%s\r\n",OBJQTYD);
					}
					
					//オブジェクトデータ分離
					for (i = 0; i < atoi(OBJQTYD); i++)
					{
						if (RX_PTR != NULL)
						{
							RX_PTR = strtok(NULL, "\r\n");
							sprintf(OBJ_DATA, "%s", RX_PTR); //OBJ_DATA ID+Type+Length+Value
							UartBrokerPrint("OBJ_DATA->%s\r\n",OBJ_DATA);
						}
						OBJ_PTR = strtok(OBJ_DATA, " ");
						if (OBJ_PTR != NULL)
						{
							sprintf(OBJ_ID[i], "%s", OBJ_PTR); //オブジェクト タグID (16進数 2桁)
							UartBrokerPrint("OBJ_ID->%s\r\n",OBJ_ID[i]);
						}
						if (OBJ_PTR != NULL)
						{
							OBJ_PTR = strtok(NULL, " ");
							sprintf(OBJ_TYPE[i], "%s", OBJ_PTR); //オブジェクト Type (16進数 2桁)
							UartBrokerPrint("OBJ_TYPE->%s\r\n",OBJ_TYPE[i]);
						}
						if (OBJ_PTR != NULL)
						{
							OBJ_PTR = strtok(NULL, " ");
							sprintf(OBJ_LEN[i], "%s", OBJ_PTR); //オブジェクト Length (16進数 2桁)
							UartBrokerPrint("OBJ_LEN->%s\r\n",OBJ_LEN[i]);
						}
						if (OBJ_PTR != NULL)
						{
							OBJ_PTR = strtok(NULL, " ");
							sprintf(OBJ_VAL[i], "%s", OBJ_PTR); //オブジェクト Value (16進数 文字列)
							UartBrokerPrint("OBJ_VAL->%s\r\n",OBJ_VAL[i]);
						}
					}
					
					//赤外線学習リモコン操作
					if (atoi(OBJ_ID[0]) == 11 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW1
					{
						UartBrokerPrint("SW1 PUSH\r\n");
						gpio_off(SW1_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW1_PIN);
					}
					if (atoi(OBJ_ID[0]) == 22 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW2
					{
						UartBrokerPrint("SW2 PUSH\r\n");
						gpio_off(SW2_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW2_PIN);
					}
					
					if (atoi(OBJ_ID[0]) == 33 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW3
					{
						UartBrokerPrint("SW3 PUSH\r\n");
						gpio_off(SW3_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW3_PIN);
					}
					
					if (atoi(OBJ_ID[0]) == 44 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW4
					{
						UartBrokerPrint("SW4 PUSH\r\n");
						gpio_off(SW4_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW4_PIN);
					}
					
					if (atoi(OBJ_ID[0]) == 55 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW5
					{
						UartBrokerPrint("SW5 PUSH\r\n");
						gpio_off(SW5_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW5_PIN);
					}

					if (atoi(OBJ_ID[0]) == 66 && strtol(OBJ_VAL[0],NULL,16) == 170) //SW6
					{
						UartBrokerPrint("SW6 PUSH\r\n");
						gpio_off(SW6_PIN);
						k_sleep(K_MSEC(100));
						gpio_on(SW6_PIN);
					}
				}
			}
        }

        if ((*REG_00_MODE == 0x01) && (prev_auth_mode == 0x00)) {
            // 認証モードがIPアドレス認証に切り替えられた
            err = SipfAuthRequest(user_name, sizeof(user_name), password, sizeof(user_name));
            LOG_DBG("SipfAuthRequest(): %d", err);
            if (err < 0) {
                // IPアドレス認証に失敗した
                *REG_00_MODE = 0x00; // モードが切り替えられなかった
            }

            err = SipfClientHttpSetAuthInfo(user_name, password);
            if (err < 0) {
                // 認証情報の設定に失敗した
                *REG_00_MODE = 0x00; // モードが切り替えられなかった
            }
        }
        prev_auth_mode = *REG_00_MODE;

        // GNSSイベントの処理
        gnss_poll();

        k_sleep(K_MSEC(1));
    }
}
