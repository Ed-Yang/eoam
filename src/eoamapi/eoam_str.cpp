#include "eoam_fsm.h"
#include "eoam_str.h"

const char *eoam_str_onoff(int onoff)
{
    static const char *ptr;

    switch (onoff)
    {
        case 1:
            ptr = "On"; break;
        case 2:
            ptr = "Off"; break;
        default:
            ptr = "--"; break;
    }

    return ptr;    
}

const char *eoam_str_oam_mode(oam_mode_e mode)
{
    static const char *ptr;

    switch (mode)
    {
        case OAM_MODE_ACTIVE:
            ptr = "active"; break;
        case OAM_MODE_PASSIVE:
            ptr = "passive"; break;
        case OAM_MODE_UNKNOWN:
            ptr = "unknown"; break;
        default:
            ptr = "--"; break;
    }

    return ptr;
}

const char *eoam_str_fsm_state(oam_state_e state)
{
    static const char *ptr;

    switch (state)
    {
    case ST_DISABLED:
        ptr = "DISABLED";
        break;
    case ST_FAULT:
        ptr = "FAULT";
        break;
    case ST_ACTIVE_SEND_LOCAL:
        ptr = "ACTIVE_SEND";
        break;
    case ST_PASSIVE_WAIT:
        ptr = "PASSIVE_WAIT";
        break;

    case ST_SEND_LOCAL_REMOTE:
        ptr = (char *) "LOC_REM";
        break;

    case ST_SEND_LOCAL_REMOTE_OK:
        ptr = "LOC_REM_OK";
        break;

    case ST_SEND_ANY:
        ptr = "SEND_ANY";
        break;

    default:
        ptr = "NA";
        break;
    }

    return ptr;
}

const char *eoam_str_oper(oam_oper_e oper)
{
    static const char *ptr;
    
    switch (oper)
    {
    case OPER_DISABLED:
        ptr = "disabled";
        break;
    case OPER_LINK_FAULT:
        ptr = "link-fault";
        break;
    case OPER_PASSIVE_WAIT:
        ptr = "passive-wait";
        break;
    case OPER_SEND_LOCAL:
        ptr = "send-local";
        break;

    case OPER_LOCAL_REMOTE:
        ptr = (char *) "send-local-remote";
        break;

    case OPER_LOCAL_REMOTE_OK:
        ptr = "send-local-remote-ok";
        break;
    case OPER_LOCAL_REJECT:
        ptr = "local-reject";
        break;
    case OPER_REMOTE_REJECT:
        ptr = "remote-reject";
        break;

    case OPER_OPERATIONAL:
        ptr = "operational";
        break;
    case OPER_HALF_DUPLEX:
        ptr = "half-duplex";
        break;
    default:
        ptr = "NA";
        break;
    }

    return ptr;
}

const char *eoam_str_events(oam_fsm_evt_e evt)
{
    static const char *ptr;

    switch (evt)
    {
    case EV_LINK_STATUS:
        ptr = "EV_LINK_STATUS";
        break;
    case EV_OAM_MODE:
        ptr = "EV_OAM_MODE";
        break;
    case EV_REMOTE_STATE_VALID:
        ptr = "EV_REMOTE_STATE_VALID";
        break;

    case EV_LOCAL_SATISFIED:
        ptr = "EV_LOCAL_SATISFIED";
        break;

    case EV_REMOTE_STABLE:
        ptr = "EV_REMOTE_STABLE";
        break;
    case EV_LOST_TIMER:
        ptr = "EV_LOST_TIMER";
        break;
    default:
        ptr = "NA";
        break;
    }

    return ptr;
}

const char *eoam_str_info_state(uint8_t state)
{
    static const char *ptr;

    switch (state)
    {
    case (STATE_PAR_FWD):
        ptr = "mux:fwd, par:fwd";
        break;
    case (STATE_PAR_LPBK):
        ptr = "mux:fwd, par:lpbk";
        break;
    case (STATE_PAR_DISCARD):
        ptr = "mux: fwd, par:drop";
        break;
    case (STATE_PAR_RESERVED):
        ptr = "mux: fwd, par:reved";
        break;
    case (STATE_MUX_DISCARD | STATE_PAR_FWD):
        ptr = "mux:drop, par:fwd";
        break;
    case (STATE_MUX_DISCARD | STATE_PAR_LPBK):
        ptr = "mux:drop, par:lpbk";
        break;
    case (STATE_MUX_DISCARD | STATE_PAR_DISCARD):
        ptr = "mux:drop, par:drop";
        break;
    case (STATE_MUX_DISCARD | STATE_PAR_RESERVED):
        ptr = "mux:drop, par:drop";
        break;
    default:
        ptr = "mux:na, par:na !!";
        break;
    }

    return ptr;
}

const char *eoam_str_info_flags(uint8_t flags, char *flag_buf)
{
    char *ptr = flag_buf;
    int l1, l2, r1, r2;

    l1 = (flags & PDU_FLAGS_L_STABLE) ? 1: 0;
    l2 = (flags & PDU_FLAGS_L_EVAL) ? 1: 0;
    r1 = (flags & PDU_FLAGS_R_STABLE) ? 1: 0;
    r2 = (flags & PDU_FLAGS_R_EVAL) ? 1: 0;

    if (((l1 + l2) & 0x01) == 0)
    {
        sprintf(flag_buf, "[%1d/%1d, %1d/%1d] !!",l1, l2, r1, r2);
    }
    else
    {
        sprintf(flag_buf, "[%1d/%1d, %1d/%1d]",l1, l2, r1, r2);
    }

    return ptr;
}

const char *eoam_str_oam_config(uint8_t config)
{
    static char config_buf[32];
    char m, u, l, e, v;

    m = (config & CFG_MODE_ACTIVE) ? 'A': 'P';
    u = (config & CFG_UNIDIRECTIONAL) ? 'U': '-';
    l = (config & CFG_LPBK) ? 'Y': '-';
    e = (config & CFG_LINK_EVENTS) ? 'Y': '-';
    v = (config & CFG_VAR_REQ) ? 'Y': '-';

    sprintf(config_buf, "M:%c/U:%c/L:%c/E:%c/V:%c",m, u, l, e, v);

    return config_buf;
}

const char *eoam_str_lpbk_status(oam_lpbk_e lpbk_status)
{
    static const char *ptr;

    switch (lpbk_status)
    {
    case NO_LPBK:
        ptr = "no loopback"; break;
    case INIT_LPBK:
        ptr = "initialing"; break;
    case REMOTE_LPBK:
        ptr = "remote loopback"; break;
    case TERM_LPBK:
        ptr = "terminationg"; break;
    case LOCAL_LPBK:
        ptr = "local loopback"; break;
    default:
        ptr = "unknown error !!!"; break;
    }

    return ptr;
}
