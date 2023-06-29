using Newtonsoft.Json.Linq;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using TachoCommon;
using TachoCommon.Utils.Ext;
using TachoCommon.Utils.Ipc.NamedPipes;
using TachoCommon.Utils.Ipc.NamedPipes.Common;
using TachoCommon.Utils.Monitoring;
using Core.Smartcard;

namespace RemoteCardAppService
{
    public static class CardReader
    {
        private static readonly string LogPrefix = $"[{Constants.SERVICE_LOCATION.Replace(".exe", "")}]";

        //#if WINDOWS_SERVICE
        //static System.Diagnostics.EventLog logger = new System.Diagnostics.EventLog();
        //#endif
        static byte[] APDUData = new byte[0];
        static Dictionary<string, byte[]> apduDataDictionary = new Dictionary<string, byte[]>();
        static Dictionary<string, byte[]> DataDictionary = new Dictionary<string, byte[]>();
        static CardBase iCard = null;
       // static APDUPlayer apduPlayer = null;
        static Dictionary<string, APDUPlayer> apduPlayerDictionary = new Dictionary<string, APDUPlayer>();
        static string IP = null;
        static string username = null;
        static string password = null;
        static int isUsed = 0;
        static string cardid = "";

        static int companyCardProtocol = (int)PROTOCOL.Undefined;
        static byte[] T0_C0_msg = null;

        //static DebugLevel debugLevel = DebugLevel.dlDebug;
        static string result = string.Empty;
        static NamedPipeServer _commsServer = null;
        static bool exceptionHappened = false;
        static int loginServerExceptionCount = 0;
        static string serverLoginError = String.Empty;


        private static void SelectICard()
        {
            try
            {
                try
                {
                    if (iCard != null)
                    {
                        Program.Logger__.Debug(LogPrefix, "Disconnect Power");
                        iCard.Disconnect(DISCONNECT.Unpower);
                        iCard.Dispose();
                    }
                }
                catch (Exception Ex)
                {
                    Program.Logger__.Error(LogPrefix, "Exception thrown 1: " + Ex.Message);

                    iCard = null;
                    ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;

                    // return;
                }

                Program.Logger__.Debug(LogPrefix, "CardNative implementation used");
                iCard = new CardNative();

                iCard.OnCardInserted += ICard_OnCardInserted;
                iCard.OnCardRemoved += ICard_OnCardRemoved;
            }
            catch (Exception ex)
            {
                Program.Logger__.Error(LogPrefix, "Exception thrown 2:" + ex.Message);
            }
        }

        private static void ICard_OnCardRemoved(object sender, string reader)
        {
            if (ServiceMonitor.ServiceStatus > ServiceState.DETECTING_CARD__ATR)
            {
                Program.Logger__.Warning(LogPrefix, "Card Status Changed, Reset to State 0");
                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
            }
        }

        private static void ICard_OnCardInserted(object sender, string reader)
        {
            if (ServiceMonitor.ServiceStatus > ServiceState.DETECTING_CARD__ATR)
            {
                Program.Logger__.Warning(LogPrefix, "Card Status Changed, Reset to State 0");
                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
            }
        }

        //private static void debug (string dt, DebugLevel log_level = DebugLevel.dlInformation)
        //{
        //    if (log_level > debugLevel)
        //    {
        //        return;
        //    }

        //    logger.WriteEntry (dt, (EventLogEntryType) log_level, event_id);
        //}

        #region old zetaipc event listener
        //private static void Comms_ReceivedRequest(object sender, ReceivedRequestEventArgs e)
        //{
        //    string cmd = e.Request;
        //    string result = "";

        //    if (cmd.Trim() == "STATE")
        //    {
        //        result = "STATE:" + ((int)ServiceMonitor.ServiceStatus).ToString() + "," + username + "," + IP;
        //    }

        //    if (cmd.Length >= "CONNECT".Length )
        //    {
        //        result = "OK";
        //    }

        //    if (cmd.Length > 6)
        //        if (cmd.Substring(0,6) == "CONFIG")
        //        {
        //            ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;  // reset to login
        //            result = "OK";
        //        }

        //    if ( result.Length == 0 )
        //    {
        //        Logger.Error (LogPrefix, "Unknown IPC Command: " + cmd);
        //        result = "UNKNOWNCMD:" + cmd;
        //    }

        //    e.Response = result;
        //    e.Handled = true;
        //}
        #endregion

        private static int DetectProtocol(int card_protocol, byte[] msg_in)
        {
            byte command = msg_in[0];
            byte instruction = msg_in[1];
            int length = msg_in.Length;
            int protocol = (int)PROTOCOL.T0orT1;

            Program.Logger__.Error(LogPrefix, "Detecting protocol: card_protocol = " + card_protocol.ToString());
            Program.Logger__.Error(LogPrefix, "Detecting protocol: command = " + command.ToString("X") + ", instruction = " + instruction.ToString("X") + ", lenght = " + length.ToString());

            switch (command)
            {
                case 0x00:
                    if (instruction == 0x88)
                    {
                        if (length == 22)
                        {
                            protocol = (int)PROTOCOL.T1;
                        }
                        if (length == 21)
                        {
                            protocol = (int)PROTOCOL.T0;
                        }
                    }

                    break;

                case 0x0C:
                    if (instruction == 0xB0)
                    {
                        if (length == 15 || length == 19)
                        {
                            protocol = (int)PROTOCOL.T1;
                        }
                        if (length == 14)
                        {
                            protocol = (int)PROTOCOL.T0;
                        }
                    }
                    if (instruction == 0xD6)
                    {
                        if ((msg_in[6] + 13) == length)
                        {
                            protocol = (int)PROTOCOL.T0;
                        }
                        else
                        {
                            protocol = (int)PROTOCOL.T1;
                        }
                    }

                    break;

                default:
                    if (instruction == 0x88 || instruction == 0xC0 || instruction == 0xD6)
                    {
                        protocol = (int)PROTOCOL.Undefined;
                        break;
                    }

                    break;
            }
            Program.Logger__.Error(LogPrefix, "protocol protocol: = " + protocol);
            if (protocol == card_protocol)
            {
                Program.Logger__.Information(LogPrefix, "Detected protocol = Card protocol");

                protocol = (int)PROTOCOL.T0orT1;
            }

            return protocol;
        }

        private static byte[] ReadCard(int detected_protocol, byte[] msg_in, APDUPlayer apduPlayer)
        {
            Program.Logger__.Information(LogPrefix, "Message_in Data Size:" + msg_in.Length);
            Program.Logger__.Information(LogPrefix, "Message_in Data: " + msg_in.ToHexString());
            Program.Logger__.Error(LogPrefix, "detected_protocol: " + detected_protocol);
            byte command = msg_in[0];
            byte instruction = msg_in[1];

            Program.Logger__.Error(LogPrefix, "Class: " + command.ToString("X"));
            Program.Logger__.Error(LogPrefix, "Ins: " + instruction.ToString("X"));

            byte[] converted_msg = null;
            byte[] reply_msg = null;
            bool error = false;

            switch (detected_protocol)
            {
                case (int)PROTOCOL.T0orT1:
                    Program.Logger__.Information(LogPrefix, "Detected protocol = T0orT1");

                    converted_msg = new byte[msg_in.Length];
                    Array.Copy(msg_in, 0, converted_msg, 0, converted_msg.Length);

                    break;

                case (int)PROTOCOL.T0:
                    Program.Logger__.Error(LogPrefix, "Detected protocol = T0");

                    if (command == 0xC0)
                    {
                        if ((T0_C0_msg == null) || (T0_C0_msg.Length <= 5))
                        {
                            error = true;

                            Program.Logger__.Warning(LogPrefix, "Illegal msg T0_C0_msg.Length == null or T0_C0_msg.Length <= 5");

                            break;
                        }

                        converted_msg = new byte[T0_C0_msg.Length];
                        Array.Copy(T0_C0_msg, 0, converted_msg, 0, converted_msg.Length);

                        Program.Logger__.Warning(LogPrefix, "Using T0_C0_msg length = " + converted_msg.Length.ToString());

                        break;
                    }
                    T0_C0_msg = new byte[msg_in.Length + 1];
                    Array.Copy(msg_in, 0, T0_C0_msg, 0, msg_in.Length);

                    reply_msg = new byte[2];
                    reply_msg[0] = 0x61;

                    if (instruction == 0x88)
                    {
                        T0_C0_msg[msg_in.Length] = 0x80;
                        reply_msg[1] = 0x80;
                    }
                    if (instruction == 0xB0)
                    {
                        Program.Logger__.Error(LogPrefix, "instruction == 0xB0");
                        T0_C0_msg[msg_in.Length] = 0x00;
                        reply_msg[1] = msg_in[7];
                    }
                    if (instruction == 0xD6)
                    {
                        T0_C0_msg[msg_in.Length] = 0x00;
                        reply_msg[1] = 0x0A;
                    }

                    Program.Logger__.Error(LogPrefix, "Dummy reply on command == 0xC0");

                    return reply_msg;

                case (int)PROTOCOL.T1:
                    Program.Logger__.Information(LogPrefix, "Detected protocol = T1");

                    APDUResponse apduResp_tmp = null;
                    APDUParam apduParam_tmp = new APDUParam
                    {
                        P1 = msg_in[2],
                        P2 = msg_in[3],
                        Le = msg_in[4]
                    };

                    if (instruction == 0x88)
                    {
                        apduParam_tmp.Data = new byte[(21 - 5)];
                        Array.Copy(msg_in, 5, apduParam_tmp.Data, 0, apduParam_tmp.Data.Length);

                        apduResp_tmp = apduPlayer.ProcessCommand(command.ToString("X"), instruction.ToString("X"), apduParam_tmp);
                    }
                    if (instruction == 0xB0)
                    {
                        if (msg_in.Length == 19)
                        {
                            Program.Logger__.Error(LogPrefix, "instruction == 0xB0 and lenght 19");
                            apduParam_tmp.Data = new byte[(18 - 5)];
                            Array.Copy(msg_in, 5, apduParam_tmp.Data, 0, apduParam_tmp.Data.Length);
                        }
                        else
                        {
                            Program.Logger__.Error(LogPrefix, "instruction == 0xB0 and lenght 15");
                            apduParam_tmp.Data = new byte[(14 - 5)];
                            Array.Copy(msg_in, 5, apduParam_tmp.Data, 0, apduParam_tmp.Data.Length);
                        }


                        Program.Logger__.Error(LogPrefix, "apduParam_Read card on instruction == 0xB0 " + apduParam_tmp.Data.ToHexString());
                        apduResp_tmp = apduPlayer.ProcessCommand(command.ToString("X"), instruction.ToString("X"), apduParam_tmp);
                    }

                    if (apduResp_tmp == null)
                    {
                        Program.Logger__.Error(LogPrefix, "Error apduResp returned null");

                        error = true;
                    }

                    if ((apduResp_tmp.Data != null) && (apduResp_tmp.Data.Length != 2))
                    {
                        int data_len1 = (apduResp_tmp.Data == null) ? 0 : apduResp_tmp.Data.Length;
                        reply_msg = new byte[data_len1 + 2];
                        if (data_len1 > 0)
                        {
                            Array.Copy(apduResp_tmp.Data, 0, reply_msg, 0, data_len1);
                        }
                        reply_msg[reply_msg.Length - 2] = BitConverter.GetBytes(apduResp_tmp.Status)[1];
                        reply_msg[reply_msg.Length - 1] = BitConverter.GetBytes(apduResp_tmp.Status)[0];

                        Program.Logger__.Error(LogPrefix, "apduParam_Reply on instruction == 0x88/0xB0 length = " + reply_msg.Length.ToString());

                        return reply_msg;
                    }

                    if (apduResp_tmp.Data != null)
                    {
                        Program.Logger__.Error(LogPrefix, "First reply on T1 instruction = " + apduResp_tmp.Data.ToHexString());
                    }

                    byte resp_1 = BitConverter.GetBytes(apduResp_tmp.Status)[0];

                    converted_msg = new byte[5];
                    converted_msg[0] = 0x00;
                    converted_msg[1] = 0xC0;
                    converted_msg[2] = 0x00;
                    converted_msg[3] = 0x00;
                    converted_msg[4] = resp_1;
                    Program.Logger__.Error(LogPrefix, "Data changed here ");

                    break;

                default:
                    Program.Logger__.Error(LogPrefix, "Error detected protocol unknown = " + detected_protocol.ToString());

                    error = true;

                    break;
            }

            if (error)
            {
                reply_msg = new byte[2];
                reply_msg[0] = 0x67;
                reply_msg[1] = 0x00;

                return reply_msg;
            }

            APDUResponse apduResp = null;
            APDUParam apduParam = new APDUParam();

            command = converted_msg[0];
            instruction = converted_msg[1];
            apduParam.P1 = converted_msg[2]; // bP1
            apduParam.P2 = converted_msg[3]; // bP2
            apduParam.Le = converted_msg[4]; // bLE
            Program.Logger__.Error(LogPrefix, "P1: " + apduParam.P1.ToString("X"));
            Program.Logger__.Error(LogPrefix, "P2: " + apduParam.P2.ToString("X"));
            Program.Logger__.Error(LogPrefix, "Le: " + apduParam.Le.ToString("X"));

            if (converted_msg.Length > 5)
            {
                apduParam.Data = new byte[converted_msg.Length - 5];
                Array.Copy(converted_msg, 5, apduParam.Data, 0, apduParam.Data.Length);

                Program.Logger__.Error(LogPrefix, "apduParam_Converted data to card reader: " + apduParam.Data.ToHexString());
            }
            Program.Logger__.Error(LogPrefix, "apduParam_command_instruction " + command.ToString("X") + "  " + instruction.ToString("X"));
            apduResp = apduPlayer.ProcessCommand(command.ToString("X"), instruction.ToString("X"), apduParam);
            Program.Logger__.Error(LogPrefix, "apduResp_response " + apduResp.ToString());

            int data_len2 = (apduResp.Data == null) ? 0 : apduResp.Data.Length;
            reply_msg = new byte[data_len2 + 2];
            if (data_len2 > 0)
            {
                Program.Logger__.Error(LogPrefix, "apduResp_response " + apduResp.Data.ToHexString());
                Program.Logger__.Error(LogPrefix, "apduResp_responseLength " + apduResp.Data.Length);
                Array.Copy(apduResp.Data, 0, reply_msg, 0, data_len2);
            }
            reply_msg[reply_msg.Length - 2] = BitConverter.GetBytes(apduResp.Status)[1];
            reply_msg[reply_msg.Length - 1] = BitConverter.GetBytes(apduResp.Status)[0];
            Program.Logger__.Error(LogPrefix, "apduResp_reply_msg " + reply_msg.ToHexString());
            if (reply_msg.ToHexString() == "[61][16]")
            {
                Program.Logger__.Error(LogPrefix, "apduResp_come_hereeeee");
                apduParam = new APDUParam();
                apduParam.Le = Convert.ToByte("16", 16);
                apduResp = apduPlayer.ProcessCommand("00", "c0", apduParam);
                Program.Logger__.Error(LogPrefix, "apduResp_response[61] " + apduResp.ToString());
                data_len2 = (apduResp.Data == null) ? 0 : apduResp.Data.Length;
                reply_msg = new byte[data_len2 + 2];
                if (data_len2 > 0)
                {
                    Program.Logger__.Error(LogPrefix, "apduResp_response " + apduResp.Data.ToHexString());
                    Program.Logger__.Error(LogPrefix, "apduResp_responseLength " + apduResp.Data.Length);
                    Array.Copy(apduResp.Data, 0, reply_msg, 0, data_len2);
                }
                reply_msg[reply_msg.Length - 2] = BitConverter.GetBytes(apduResp.Status)[1];
                reply_msg[reply_msg.Length - 1] = BitConverter.GetBytes(apduResp.Status)[0];
                /*if (apduResp.ToString().Contains("61"))
                {
                    apduParam = new APDUParam();
                    apduParam.Le = Convert.ToByte("12", 16);
                    apduResp = apduPlayer.ProcessCommand("00", "c0", apduParam);
                    Program.Logger__.Error(LogPrefix, "aaaaaaaaaaaaaaaa[61] " + apduResp.ToString());
                    Program.Logger__.Error(LogPrefix, "recursive_called " + apduResp.ToString());
                }*/
            }
            if (reply_msg.ToHexString() == "[6C][04]" || reply_msg.ToHexString() == "[6C][05]")
            {
                Program.Logger__.Error(LogPrefix, "apduResp_come_hereeeee");
                if (reply_msg.ToHexString() == "[6C][04]")
                {
                    apduParam.Le = 0x04;
                }
                if (reply_msg.ToHexString() == "[6C][05]")
                {
                    apduParam.Le = 0x05;
                }
                apduResp = apduPlayer.ProcessCommand(command.ToString("X"), instruction.ToString("X"), apduParam);
                Program.Logger__.Error(LogPrefix, "apduResp_response[6C] " + apduResp.ToString());
                data_len2 = (apduResp.Data == null) ? 0 : apduResp.Data.Length;
                reply_msg = new byte[data_len2 + 2];
                if (data_len2 > 0)
                {
                    Program.Logger__.Error(LogPrefix, "apduResp_response " + apduResp.Data.ToHexString());
                    Program.Logger__.Error(LogPrefix, "apduResp_responseLength " + apduResp.Data.Length);
                    Array.Copy(apduResp.Data, 0, reply_msg, 0, data_len2);
                }
                reply_msg[reply_msg.Length - 2] = BitConverter.GetBytes(apduResp.Status)[1];
                reply_msg[reply_msg.Length - 1] = BitConverter.GetBytes(apduResp.Status)[0];
                /*if (apduResp.ToString().Contains("61"))
                {
                    apduParam = new APDUParam();
                    apduParam.Le = Convert.ToByte("12", 16);
                    apduResp = apduPlayer.ProcessCommand("00", "c0", apduParam);
                    Program.Logger__.Error(LogPrefix, "aaaaaaaaaaaaaaaa[61] " + apduResp.ToString());
                    Program.Logger__.Error(LogPrefix, "recursive_called " + apduResp.ToString());
                }*/
            }
            return reply_msg;
        }
   


        public static void Run(string[] args, ref bool quit)
        {
            //Thread.Sleep(10000);
            if (!Directory.Exists(Constants.APP_LOGS_DIR))
            {
                Directory.CreateDirectory(Constants.APP_LOGS_DIR);
            }

            if (args.Length == 1)
            {
                switch (args[0])
                {
                    case "-f":
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Fatal);
                        break;

                    case "-e":
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Error);
                        break;

                    case "-w":
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Warning);
                        break;

                    case "-i":
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Information);
                        break;

                    case "-d":
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Debug);
                        break;

                    default:
                        Program.Logger__.SetMinimumLogLevel(LogEventLevel.Information);
                        break;
                }
            }

            if (args != null && args.Length > 0)
            {
                Program.Logger__.Error(LogPrefix, $"RemoteCard App Service ({args[0]})");
            }
            else
            {
                Program.Logger__.Error(LogPrefix, $"RemoteCard App Service (Started without any arguments)");
            }

            //Thread.Sleep(3000); // Sleep 3 seconds to give comms port time to initialise when running as a Windows service  

            // start ipc server
            //var comms = new IpcServer();
            //comms.ReceivedRequest += Comms_ReceivedRequest;
            //comms.Start(12345);

            //Logger.Information(LogPrefix, "Started IPC Server");

            _commsServer = new NamedPipeServer();
            _commsServer.OnMessageReceived += CommsServer_OnMessageReceived;
            //commsServer.SendMessage += CommsServer_SendMessage;
            _commsServer.Launch();
            Program.Logger__.Information(LogPrefix, $"Started Named Pipe Server");


            // init card
            string cardReader = "";

            byte[] atrValue = null;
            string ATR = "";
            string msg_id = "";
            string terminal_serial = "";

            ServicePointManager.ServerCertificateValidationCallback = (senderX, certificate, chain, sslPolicyErrors) => { return true; };

            string sessionToken = String.Empty;

            List<string> sListReaders = new List<string>(1);

            // DEBUG
            Program.Logger__.Information(LogPrefix, $"(Run Method) App Working Dir: {AppDomain.CurrentDomain.BaseDirectory}");

            ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
            //Program.Logger__.Error(LogPrefix, "status alan DETECTING_CARD_READER hast");
            while (!quit)
            {
                Program.Logger__.Debug(LogPrefix, $"State: {ServiceMonitor.ServiceStatus}");
                switch (ServiceMonitor.ServiceStatus)
                {
                    case ServiceState.DETECTING_CARD_READER: // card reader attached?
                        SelectICard();

                        try
                        {
                            iCard.StopCardEvents();
                            sListReaders = iCard.ListReaders()?.ToList(); ;
                            if ((sListReaders == null) || (sListReaders.Count < 1))
                            {
                                Program.Logger__.Error(LogPrefix, $"Error: No Card Readers Detected");
                                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
                                Program.Logger__.Error(LogPrefix, "waittt1");
                                Thread.Sleep(5000);
                            }
                            else
                            {
                                //Program.Logger__.Error(LogPrefix, $"{sListReaders.Count} card readers detected");
                                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD__ATR;
                            }
                        }
                        catch (Exception Ex)
                        {
                            Program.Logger__.Debug(LogPrefix, "No Card Readers Detected");
                            //Program.Logger__.Error(LogPrefix, "Exception thrown 3: " + Ex.Message + "\n" + Ex.StackTrace);
                            ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
                            Program.Logger__.Error(LogPrefix, "waittt2");
                            Thread.Sleep(10000);
                        }

                        break;

                    case ServiceState.DETECTING_CARD__ATR: // card inserted, get atr ?
                        try
                        {
                            //Program.Logger__.Error(LogPrefix, "oomad inja alan");
                            Program.Logger__.Error(LogPrefix, $"sListReaders {string.Join("\n", sListReaders)}");
                            foreach (var rdrName in sListReaders)
                            {
                                //Program.Logger__.Error(LogPrefix, $"Attempting to connect to {rdrName}...");
                                try
                                {
                                    iCard.StartCardEvents(rdrName);
                                    cardReader = rdrName;
                                    iCard.Connect(rdrName, SHARE.Shared, PROTOCOL.T0);
                                    Program.Logger__.Error(LogPrefix, "Selecting " + cardReader);
                                    //Program.Logger__.Error(LogPrefix, "11111");
                                    ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD__ATR;
                                    break;
                                }
                                catch (Exception ex)
                                {
                                    //Program.Logger__.Error(LogPrefix, "khataaa daadddd");
                                    //Program.Logger__.Error(LogPrefix, $"Failed in connecting to {rdrName}: {ex.Message}");
                                    iCard.StopCardEvents();
                                }
                            }

                            try
                            {
                                Program.Logger__.Error(LogPrefix, $"cardReader to connect {cardReader}...");
                                iCard.Connect(cardReader, SHARE.Shared, PROTOCOL.T0);
                            }
                            catch (SmartCardException Ex)
                            {
                                //Program.Logger__.Error(LogPrefix, $"Error: No Card Detected");
                                //Program.Logger__.Error(LogPrefix, "Exception thrown iCard.Connect(): " + Ex.Message + "\n" + Ex.StackTrace);
                            }
                            // Get the ATR of the card
                            // Program.Logger__.Error(LogPrefix, "atrValue_before=> " + atrValue);
                            atrValue = iCard.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                            // Program.Logger__.Error(LogPrefix, "atrValue_After_8=> " + Encoding.ASCII.GetString(atrValue));

                            byte[] device_friendlyname = iCard.GetAttribute(SCARD_ATTR_VALUE.DEVICE_FRIENDLY_NAME);
                            // Program.Logger__.Information(LogPrefix, "device friendlyname: " + Encoding.ASCII.GetString(device_friendlyname));
                            // Program.Logger__.Error(LogPrefix, "device friendlyname: " + Encoding.ASCII.GetString(device_friendlyname));
                            byte[] protocol_types = iCard.GetAttribute(SCARD_ATTR_VALUE.PROTOCOL_TYPES);
                            // Program.Logger__.Information(LogPrefix, "protocol_types: " + protocol_types.ToHexString());
                            byte[] current_protocol_type = iCard.GetAttribute(SCARD_ATTR_VALUE.CURRENT_PROTOCOL_TYPE);
                            // Program.Logger__.Information(LogPrefix, "current_protocol_type: " + current_protocol_type.ToHexString());

                            //ATR = ByteArray.ToString(atrValue);
                            ATR = Convert.ToBase64String(atrValue);
                            // Program.Logger__.Error(LogPrefix, "ATR=> " + ATR);

                            // not sure if ATR is sufficient for cardreader id, might need to poll a specific apdu to get another id
                            cardid = atrValue.ToHexString();
                            // Program.Logger__.Error(LogPrefix, "cardid=> " + cardid);
                            if (string.IsNullOrEmpty(cardid))
                            {
                                //Program.Logger__.Error(LogPrefix, "22222");
                                //Program.Logger__.Error(LogPrefix, "Card id is empty on iCard.Connect, Reset to State 0");
                                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;

                                break;
                            }

                            Program.Logger__.Information(LogPrefix, "ATR:" + atrValue.ToHexString());
                            Program.Logger__.Information(LogPrefix, "ATR:" + ATR);
                            //Program.Logger__.Error(LogPrefix, "CARD_ATR:" + ATR);

                           // apduPlayer = new APDUPlayer(iCard);
                            //Program.Logger__.Error(LogPrefix, "333333");
                            ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;
                        }
                        catch (Exception Ex)
                        {
                            //Program.Logger__.Error(LogPrefix, "444444");

                            ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD_READER;
                            //Program.Logger__.Error(LogPrefix, $"Cannot Connect Smart Card: {Ex.Message}\n{Ex.StackTrace}");
                        }

                        break;

                    case ServiceState.SERVER_SIGNING_IN:
                        Program.Logger__.Information(LogPrefix, "ready to login");
                        Program.Logger__.Error(LogPrefix, "ready to login");
                        //Program.Logger__.Error(LogPrefix, "Hereeeee");
                        //Program.Logger__.Error(LogPrefix, "statusssss Hereeeee=> " + ServiceMonitor.ServiceStatus.ToString());
                        var creds = new Credentials();
                        IP = creds.IP__;
                        isUsed = creds.IsUsed__;
                        Program.Logger__.Error(LogPrefix, "SSSSSSSSSSSSSSSSSSSSSSSSSSSS=> " + IP + " " + isUsed);
                        if (!string.IsNullOrWhiteSpace(sessionToken) && isUsed == 1)
                        {
                            ServiceMonitor.ServiceStatus = ServiceState.WAITING_FOR_DATA;
                            break;
                        }
                        if (string.IsNullOrWhiteSpace(IP))
                        {
                            break;
                        }


                        username = creds.Username__;
                        password = creds.Password__;
                        Program.Logger__.Error(LogPrefix, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=> " + username + " " + password);

                        var url = $"https://{IP}:5200/mswitch/tach/login";
                        HttpWebResponse response = null;

                        try
                        {
                            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                            request.Method = "POST";
                            //Program.Logger__.Error(LogPrefix, "Hereeeee 11");
                            request.ContentType = "application/json";
                            request.UserAgent = "Cartrack web client";
                            request.Headers.Add("Authorization: Bearer { CARTRACK_R & D_1}");
                            request.Headers.Add("ATR: " + ATR);
                            request.Timeout = 100000;
                            request.KeepAlive = false;

                            string postData = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\", \"card_id\":\"" + cardid + "\"}";
                            Program.Logger__.Error(LogPrefix, "postData=> " + postData);
                            ASCIIEncoding encoding = new ASCIIEncoding();
                            byte[] byte1 = encoding.GetBytes(postData);
                            request.ContentLength = byte1.Length;
                            //Program.Logger__.Error(LogPrefix, "Hereeeee 22");
                            Stream reqStream = request.GetRequestStream();
                            reqStream.Write(byte1, 0, byte1.Length);
                            reqStream.Close();
                            //Program.Logger__.Error(LogPrefix, "Hereeeee 33");
                            response = (HttpWebResponse)request.GetResponse();
                            Stream dataStream = response.GetResponseStream();
                            StreamReader reader = new StreamReader(dataStream);
                            string txtResponse = reader.ReadToEnd();

                            Program.Logger__.Error(LogPrefix, "Status: " + response.StatusCode);
                            Program.Logger__.Error(LogPrefix, "Response 1: " + txtResponse);

                            bool i = creds.updateUsedPassword();
                            Program.Logger__.Error(LogPrefix, "updateUsedPassword_updateUsedPassword 1: " + i);

                            JObject output = JObject.Parse(txtResponse);
                            serverLoginError = String.Empty;
                            Program.Logger__.Information(LogPrefix, output["session_token"].ToString());
                            sessionToken = output["session_token"].ToString();
                            //Program.Logger__.Error(LogPrefix, "Hereeeee 4444");
                            ServiceMonitor.ServiceStatus = ServiceState.WAITING_FOR_DATA;
                        }
                        catch (WebException Ex)
                        {
                            //ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD__ATR;
                            if (loginServerExceptionCount > 2)
                            {
                                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD__ATR;
                            }
                            exceptionHappened = true;
                            loginServerExceptionCount++;
                            if (Ex.Message.Contains("401"))
                            {
                                serverLoginError = "unauthorized";
                                Program.Logger__.Error(LogPrefix, "unauthorized");
                            }
                            else
                              if (Ex.Message.Contains("Unable to connect"))
                            {
                                serverLoginError = "request_timed_out";
                                Program.Logger__.Error(LogPrefix, "Request timed out");
                            }
                            int errr = 0;
                            if (Ex.Status == WebExceptionStatus.ProtocolError)
                            {
                                var responseCode = Ex.Response as HttpWebResponse;
                                if (responseCode != null)
                                {
                                    Program.Logger__.Error(LogPrefix, "HTTP Status Code: " + (int)responseCode.StatusCode);
                                    errr = (int)responseCode.StatusCode;
                                }
                                else
                                {
                                }
                            }
                            else
                            {
                            }
                            Program.Logger__.Error(LogPrefix, $"WebException thrown at server login\nMessage: {Ex.Message}" +
                                $"\nURL: {url}\nHTTP Status: {errr}\nStatus: {Ex.Status}\nResponse: {Ex.Response}\nData: {Ex.Data}");
                        }
                        catch (Exception Ex)
                        {
                            Program.Logger__.Error(LogPrefix, "Exception thrown 4:" + Ex.Message);
                            Program.Logger__.Error(LogPrefix, "waittt3");
                            Thread.Sleep(5000);
                        }

                        break;

                    case ServiceState.WAITING_FOR_DATA:

                        try
                        {
                            var credentials = new Credentials();
                            isUsed = credentials.IsUsed__;
                            if (isUsed == 0)
                            {
                                ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;
                                break;
                            }
                            Program.Logger__.Debug(LogPrefix, "get apdu request");
                            Program.Logger__.Error(LogPrefix, "serverLoginError_val 2 " + serverLoginError);
                            HttpWebRequest apdu_request = (HttpWebRequest)WebRequest.Create("https://" + IP + ":5200/mswitch/tach/" + username + "/authentication");

                            apdu_request.Method = "GET";
                            apdu_request.ContentType = "application/json";
                            apdu_request.UserAgent = "Cartrack web client";
                            apdu_request.Headers.Add("Authorization: Bearer { CARTRACK_R & D_1}");
                            apdu_request.Headers.Add("session_token: " + sessionToken);
                            apdu_request.Timeout = 100000;
                            apdu_request.KeepAlive = false;

                            HttpWebResponse apdu_response = (HttpWebResponse)apdu_request.GetResponse();
                            Stream apdu_dataStream = apdu_response.GetResponseStream();
                            StreamReader aptdu_reader = new StreamReader(apdu_dataStream);
                            string apdu_txtResponse = aptdu_reader.ReadToEnd();

                            Program.Logger__.Debug(LogPrefix, "Status: " + apdu_response.StatusCode);
                            Program.Logger__.Debug(LogPrefix, "Response 2: " + apdu_txtResponse);
                            serverLoginError = String.Empty;
                            Program.Logger__.Error(LogPrefix, "Status Response 2: => " + apdu_response.StatusCode + "  " + apdu_txtResponse);

                            JObject dataObject = JObject.Parse(apdu_txtResponse);

                            Program.Logger__.Debug(LogPrefix, "msg id: " + dataObject["msg_id"].ToString());
                            Program.Logger__.Debug(LogPrefix, "data: " + dataObject["data"].ToString());

                            msg_id = dataObject["msg_id"].ToString();
                            terminal_serial = dataObject["serial"].ToString();
                            byte cmd = 0x00;

                            try
                            {
                                byte[] data = Convert.FromBase64String(dataObject["data"].ToString());
                                DataDictionary[terminal_serial] = data;
                                Program.Logger__.Error(LogPrefix, "Size: " + data.Length.ToString() + "," + data.ToHexString());

                                if (DataDictionary[terminal_serial] != null && DataDictionary[terminal_serial].Length > 0)
                                {
                                    cmd = DataDictionary[terminal_serial][0];
                                    Program.Logger__.Error(LogPrefix, "cmd: " + cmd.ToString());

                                    if (cmd == 0x04)
                                    {
                                        APDUData = new byte[DataDictionary[terminal_serial].Length - 1];
                                        apduDataDictionary[terminal_serial] = APDUData;

                                        Array.Copy(data, 1, apduDataDictionary[terminal_serial], 0, apduDataDictionary[terminal_serial].Length);
                                        Program.Logger__.Error(LogPrefix, "APDUData on cmd 0x04: " + apduDataDictionary[terminal_serial].ToString());
                                    }
                                }
                                else
                                {
                                    Program.Logger__.Information(LogPrefix, "No data in the response");
                                }
                            }
                            catch (Exception Ex)
                            {
                                Program.Logger__.Error(LogPrefix, "Exception thrown 5: " + Ex.Message);
                            }

                            Program.Logger__.Error(LogPrefix, "cmd: " + cmd.ToString());


                            if (cmd == 4)
                            {
                                if (dataObject["data"].ToString().Length > 4)
                                {
                                    Program.Logger__.Error(LogPrefix, "APDU for Company Card: " + apduDataDictionary[terminal_serial].ToHexString());
                                    int detected_protocol = DetectProtocol(companyCardProtocol, apduDataDictionary[terminal_serial]);
                                    apduDataDictionary[terminal_serial] = ReadCard(detected_protocol, apduDataDictionary[terminal_serial], apduPlayerDictionary[terminal_serial]);
                                    Program.Logger__.Error(LogPrefix, "Reply to Tach: " + apduDataDictionary[terminal_serial].ToHexString());

                                    ServiceMonitor.ServiceStatus = ServiceState.PROCESSING_DATA;
                                }
                                else
                                {
                                    if (dataObject["data"].ToString().Length > 0)
                                    {
                                        Program.Logger__.Warning(LogPrefix, $"Error: Data Packet too small");
                                    }
                                    Program.Logger__.Error(LogPrefix, "waittt4");
                                    Thread.Sleep(5000);
                                }
                            }

                            if (cmd == 0x03)
                            {
                                Program.Logger__.Information(LogPrefix, "Card Reset");
                                try
                                {
                                    Program.Logger__.Error(LogPrefix, "terminal_serial inside icarddic " + terminal_serial);
                                    iCard.Disconnect(DISCONNECT.Reset);
                                }
                                catch (Exception Ex)
                                {
                                    Program.Logger__.Error(LogPrefix, "Exception thrown 6: " + Ex.Message);
                                }

                                iCard.Connect(cardReader, SHARE.Shared, PROTOCOL.T0);

                                byte[] protocol_types = iCard.GetAttribute(SCARD_ATTR_VALUE.PROTOCOL_TYPES);
                                Program.Logger__.Information(LogPrefix, "protocol_types: " + protocol_types.ToHexString());
                                companyCardProtocol = BitConverter.ToInt32(iCard.GetAttribute(SCARD_ATTR_VALUE.CURRENT_PROTOCOL_TYPE), 0);
                                Program.Logger__.Information(LogPrefix, "current_protocol_type: " + companyCardProtocol.ToString());

                                // Get the ATR of the card
                                apduDataDictionary[terminal_serial] = iCard.GetAttribute(SCARD_ATTR_VALUE.ATR_STRING);
                                //ATR = ByteArray.ToString(atrValue);

                                Program.Logger__.Information(LogPrefix, "ATR:" + atrValue.ToHexString());
                                Program.Logger__.Information(LogPrefix, "ATR:" + ATR);
                                Program.Logger__.Error(LogPrefix, "ATR:" + ATR);
                                Program.Logger__.Error(LogPrefix, "TOUCH HERE " + cmd.ToString());
                                apduPlayerDictionary[terminal_serial] = new APDUPlayer(iCard);

                                Program.Logger__.Information(LogPrefix, "Result: " + apduDataDictionary[terminal_serial].ToHexString());

                                ServiceMonitor.ServiceStatus = ServiceState.PROCESSING_DATA;
                            }

                            if (cmd == 0)
                            {
                                Program.Logger__.Error(LogPrefix, "waittt5");
                                Thread.Sleep(200);
                            }
                        }
                        catch (Exception Ex)
                        {
                            Program.Logger__.Error(LogPrefix, "Exception thrown 7: " + Ex.Message);
                            if (Ex.Message.Contains("SCardConnect"))
                            {
                                ServiceMonitor.ServiceStatus = ServiceState.DETECTING_CARD__ATR;
                            }
                            else if (Ex.Message.Contains("Unable to connect"))
                            {
                                serverLoginError = "request_timed_out";
                                Program.Logger__.Error(LogPrefix, "request_timed_out");
                            }
                            else if (Ex.Message.Contains("401"))
                            {
                                serverLoginError = "unauthorized";
                                Program.Logger__.Error(LogPrefix, "unauthorized");
                                var cred = new Credentials();
                                cred.updateUsedPassword("data_server_credentials", 0);
                                ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;
                            }
                            else
                            {
                                ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;
                            }
                            Program.Logger__.Error(LogPrefix, "waittt6");
                            Thread.Sleep(5000);
                        }

                        break;

                    case ServiceState.PROCESSING_DATA:

                        try
                        {
                            Program.Logger__.Error(LogPrefix, "zzzzzzzzzz before base64: " + apduDataDictionary[terminal_serial].ToHexString());
                            string returnData = Convert.ToBase64String(apduDataDictionary[terminal_serial]);
                            Program.Logger__.Error(LogPrefix, "zzzzzzzzzz after base64: " + returnData);

                            Program.Logger__.Information(LogPrefix, "Return Data: " + returnData);
                            Program.Logger__.Information(LogPrefix, "Msg Id: " + msg_id);
                            Program.Logger__.Error(LogPrefix, "PROCESSING_DATA Msg Id: " + msg_id);
                            Program.Logger__.Error(LogPrefix, "PROCESSING_DATA terminal_serial: " + terminal_serial);

                            HttpWebRequest apdu_result = (HttpWebRequest)WebRequest.Create("https://" + IP + ":5200/mswitch/tach/" + username + "/authentication/" + msg_id + "/result");

                            apdu_result.Method = "POST";
                            apdu_result.ContentType = "application/json";
                            apdu_result.UserAgent = "Cartrack web client";
                            apdu_result.Headers.Add("Authorization: Bearer { CARTRACK_R & D_1}");
                            apdu_result.Headers.Add("session_token: " + sessionToken);
                            apdu_result.Timeout = 100000;
                            apdu_result.KeepAlive = false;

                            string apdu_requestData = "{\"session_token\": \"" + sessionToken + "\", \"data\":\"" + returnData + "\", \"terminal_serial\":\"" + terminal_serial + "\"}";

                            Program.Logger__.Information(LogPrefix, apdu_requestData);

                            ASCIIEncoding apdu_encoding = new ASCIIEncoding();
                            byte[] apdu_byteArray = apdu_encoding.GetBytes(apdu_requestData);
                            apdu_result.ContentLength = apdu_byteArray.Length;
                            Stream apdu_reqStream = apdu_result.GetRequestStream();
                            apdu_reqStream.Write(apdu_byteArray, 0, apdu_byteArray.Length);
                            apdu_reqStream.Close();


                            HttpWebResponse apdu_result_response = (HttpWebResponse)apdu_result.GetResponse();
                            Stream apdu_result_dataStream = apdu_result_response.GetResponseStream();
                            StreamReader apdu_result_reader = new StreamReader(apdu_result_dataStream);
                            string apdu_resultReponse = apdu_result_reader.ReadToEnd();

                            Program.Logger__.Error(LogPrefix, "PROCESSING_DATA Status: " + apdu_result_response.StatusCode);
                            Program.Logger__.Error(LogPrefix, "zzzzzzzzzz Response 3: " + apdu_resultReponse);

                            JObject resultObject = JObject.Parse(apdu_resultReponse);

                            Program.Logger__.Error(LogPrefix, resultObject.ToString());

                            ServiceMonitor.ServiceStatus = ServiceState.WAITING_FOR_DATA;
                        }
                        catch (Exception Ex)
                        {
                            Program.Logger__.Error(LogPrefix, "Exception thrown 8: " + Ex.Message);
                            ServiceMonitor.ServiceStatus = ServiceState.WAITING_FOR_DATA;
                            Program.Logger__.Error(LogPrefix, "waittt7");
                            Thread.Sleep(7000);
                        }

                        break;

                    default:
                        Program.Logger__.Error(LogPrefix, "* PANIC: Error, unknown state ");
                        break;
                }
            }

            try
            {
                if (iCard != null)
                {
                    iCard.StopCardEvents();
                    iCard.Dispose();
                }
                Program.Logger__.Information(LogPrefix, "Card reader terminating gracefully");
            }
            catch (Exception ex)
            {
                Program.Logger__.Information(LogPrefix, $"Error while stopping the service: {ex.Message}\n{ex.StackTrace}");
            }
            finally
            {
                quit = false;
            }
            //return state;
        }

        private static void CommsServer_SendMessage(object sender, SendMessageArgs e)
        {
            e.MessageToSend = result;
        }


        private static void CommsServer_OnMessageReceived(object sender, MessageReceivedArgs e)
        {
            result = string.Empty;
            string cmd = e.Response;


            if (cmd.Trim() == "STATE")
            {
                Program.Logger__.Error(LogPrefix, "statusssss=> " + ServiceMonitor.ServiceStatus.ToString());
                result = "STATE:" + ((int)ServiceMonitor.ServiceStatus).ToString() + "," + username + "," + IP + ",VERSION 1.19";
                Program.Logger__.Error(LogPrefix, "serverLoginError_val 3 " + serverLoginError);
                if (!string.IsNullOrWhiteSpace(serverLoginError) && (ServiceMonitor.ServiceStatus == ServiceState.SERVER_SIGNING_IN || ServiceMonitor.ServiceStatus == ServiceState.WAITING_FOR_DATA))
                {
                    result = serverLoginError;
                }
            }


            if (cmd.Length >= "CONNECT".Length)
            {
                result = "OK";
            }

            if (cmd.Length > 6)
                if (cmd.Substring(0, 6) == "CONFIG")
                {
                    ServiceMonitor.ServiceStatus = ServiceState.SERVER_SIGNING_IN;  // reset to login
                    result = "OK";
                }

            if (result.Length == 0)
            {
                Program.Logger__.Error(LogPrefix, "Unknown IPC Command: " + cmd);
                result = "UNKNOWNCMD:" + cmd;
            }
            Program.Logger__.Error(LogPrefix, "result Command: " + result);
            _commsServer.SendMessage(result);

        }
    }
}
