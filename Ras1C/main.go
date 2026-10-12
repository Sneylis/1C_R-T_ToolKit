// ras1c — инвентаризация кластера 1С:Предприятие через сервис RAS
// (Remote Administration Server), по умолчанию порт 1545.
//
// Использует чистую Go-реализацию протокола RAS (github.com/khorevaa/ras-client),
// поэтому НЕ требует установленной платформы 1С или утилиты rac на машине.
//
//    ras1c -host 10.0.0.5
//    ras1c -host 10.0.0.5 -user Администратор -password 'secret' -dump
//    ras1c -host 10.0.0.5 -dump -ib-user Администратор -ib-password 'pwd' -json
//
// Пароли можно передавать через переменные окружения вместо флагов:
//
//    RAS1C_PASSWORD     — пароль администратора кластера
//    RAS1C_IB_PASSWORD  — пароль администратора инфобазы
package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "sort"
    "strings"
    "text/tabwriter"
    "time"

    rclient "github.com/khorevaa/ras-client"
    "github.com/khorevaa/ras-client/serialize"
    uuid "github.com/satori/go.uuid"
)

func main() {
    var (
        host     = flag.String("host", "", "IP-адрес или имя сервера RAS (обязательно)")
        port     = flag.Int("port", 1545, "порт RAS")
        user     = flag.String("user", "", "администратор кластера")
        password = flag.String("password", "", "пароль администратора кластера (или env RAS1C_PASSWORD)")

        fIB    = flag.Bool("infobases", true, "список информационных баз")
        fSess  = flag.Bool("sessions", true, "список сессий")
        fProc  = flag.Bool("processes", false, "рабочие процессы (rphost)")
        fAdm   = flag.Bool("admins", false, "администраторы кластера")
        fConns = flag.Bool("connections", false, "соединения кластера")
        fLic   = flag.Bool("licenses", false, "лицензии, удерживаемые сессиями")
        fSrv   = flag.Bool("servers", false, "рабочие серверы кластера (лимиты, порты)")
        fLock  = flag.Bool("locks", false, "блокировки кластера")
        fDump  = flag.Bool("dump", false, "выгрузить ВСЮ доступную информацию (включает все срезы)")

        exportUsers = flag.String("export-users", "", "записать уникальные имена пользователей 1С из сессий в файл (построчно, без повторов) и выйти")
        exportHosts = flag.String("export-hosts", "", "записать уникальные имена хостов (NetBIOS/hostname) из сессий в файл (построчно, без повторов) и выйти")

        ibName = flag.String("infobase", "", "детальная информация по инфобазе (по имени)")
        ibUser = flag.String("ib-user", "", "администратор инфобазы (для -infobase / -dump)")
        ibPass = flag.String("ib-password", "", "пароль администратора инфобазы (или env RAS1C_IB_PASSWORD)")

        asJSON  = flag.Bool("json", false, "вывод в формате JSON")
        timeout = flag.Duration("timeout", 60*time.Second, "таймаут операции")
    )
    flag.Parse()

    if *host == "" {
        fmt.Fprintln(os.Stderr, "ошибка: не задан -host")
        flag.Usage()
        os.Exit(2)
    }

    // пароли из окружения, если флаг пуст
    pass := firstNonEmpty(*password, os.Getenv("RAS1C_PASSWORD"))
    ibPassword := firstNonEmpty(*ibPass, os.Getenv("RAS1C_IB_PASSWORD"))

    // -dump включает все read-only срезы
    ib := *fIB || *fDump
    sess := *fSess || *fDump
    proc := *fProc || *fDump
    adm := *fAdm || *fDump
    conns := *fConns || *fDump
    lic := *fLic || *fDump
    srv := *fSrv || *fDump
    lock := *fLock || *fDump
    // в режиме dump с учёткой инфобазы — детали по ВСЕМ базам
    dumpAllIB := *fDump && *ibUser != "" && *ibName == ""

    addr := fmt.Sprintf("%s:%d", *host, *port)
    ctx, cancel := context.WithTimeout(context.Background(), *timeout)
    defer cancel()

    client := rclient.NewClient(addr)
    defer client.Close()

    clusters, err := client.GetClusters(ctx)
    if err != nil {
        fmt.Fprintf(os.Stderr, "не удалось получить кластеры с %s: %v\n", addr, err)
        os.Exit(1)
    }

    // режимы экспорта: собрать уникальные значения из сессий всех кластеров,
    // записать построчно в файл и выйти. Можно указать оба флага сразу — сессии
    // запрашиваются один раз.
    if *exportUsers != "" || *exportHosts != "" {
        users := map[string]struct{}{}
        hosts := map[string]struct{}{}
        for _, cl := range clusters {
            if *user != "" {
                client.AuthenticateCluster(cl.UUID, *user, pass)
            }
            sessions, err := client.GetClusterSessions(ctx, cl.UUID)
            if err != nil {
                warn(cl.Name, "сессии", err)
                continue
            }
            for _, ss := range sessions {
                if *exportUsers != "" && ss.UserName != "" {
                    users[ss.UserName] = struct{}{}
                }
                if *exportHosts != "" && ss.Host != "" {
                    hosts[ss.Host] = struct{}{}
                }
            }
        }
        if *exportUsers != "" {
            writeLines(*exportUsers, users, "имён пользователей")
        }
        if *exportHosts != "" {
            writeLines(*exportHosts, hosts, "хостов")
        }
        return
    }

    report := Report{Server: addr, RetrievedAt: time.Now()}
    needIBMap := ib || sess || conns || lock || *ibName != "" || dumpAllIB

    for _, cl := range clusters {
        if *user != "" {
            client.AuthenticateCluster(cl.UUID, *user, pass)
        }

        cr := ClusterReport{
            UUID: cl.UUID.String(), Name: cl.Name,
            Host: cl.Host, Port: int(cl.Port), SecurityLevel: cl.SecurityLevel,
        }

        var ibByID map[uuid.UUID]string
        var ibList serialize.InfobaseSummaryList

        if needIBMap {
            ibs, err := client.GetClusterInfobases(ctx, cl.UUID)
            if err != nil {
                warn(cl.Name, "инфобазы", err)
            } else {
                ibList = ibs
                ibByID = make(map[uuid.UUID]string, len(ibs))
                for _, x := range ibs {
                    ibByID[x.UUID] = x.Name
                    if ib {
                        cr.Infobases = append(cr.Infobases, InfobaseReport{
                            UUID: x.UUID.String(), Name: x.Name, Description: x.Description,
                        })
                    }
                }
            }
        }

        if adm {
            if admins, err := client.GetClusterAdmins(ctx, cl.UUID); err != nil {
                warn(cl.Name, "администраторы", err)
            } else {
                for _, a := range admins {
                    cr.Admins = append(cr.Admins, AdminReport{
                        Name: a.Name, Description: a.Description,
                        PasswordAuth: a.PasswordAuthAllowed, OSAuth: a.SysAuthAllowed, OSUser: a.SysUserName,
                    })
                }
            }
        }

        if srv {
            if servers, err := client.GetWorkingServers(ctx, cl.UUID); err != nil {
                warn(cl.Name, "рабочие серверы", err)
            } else {
                for _, s := range servers {
                    cr.Servers = append(cr.Servers, ServerReport{
                        Name: s.Name, AgentHost: s.AgentHost, AgentPort: s.AgentPort,
                        ClusterPort: s.ClusterPort, MainServer: s.MainServer,
                        PortRange:        strings.Join(s.PortRange, ","),
                        ConnectionsLimit: s.ConnectionsLimit, InfobasesLimit: s.InfobasesLimit,
                    })
                }
            }
        }

        if proc {
            if procs, err := client.GetWorkingProcesses(ctx, cl.UUID); err != nil {
                warn(cl.Name, "процессы", err)
            } else {
                for _, p := range procs {
                    cr.Processes = append(cr.Processes, ProcessReport{
                        Host: p.Host, Port: int(p.Port), Pid: p.Pid,
                        Enable: p.Enable, Running: p.Running, MemoryKB: p.MemorySize,
                        Connections: p.Connections, AvailablePerf: p.AvailablePerfomance,
                        AvgCallTime: p.AvgCallTime, StartedAt: p.StartedAt,
                    })
                }
            }
        }

        if conns {
            if cc, err := client.GetClusterConnections(ctx, cl.UUID); err != nil {
                warn(cl.Name, "соединения", err)
            } else {
                for _, cn := range cc {
                    cr.Connections = append(cr.Connections, ConnectionReport{
                        ID: cn.ID, Host: cn.Host, Application: cn.Application,
                        Infobase: ibByID[cn.InfobaseID], SessionID: cn.SessionID, ConnectedAt: cn.ConnectedAt,
                    })
                }
            }
        }

        if sess {
            if sessions, err := client.GetClusterSessions(ctx, cl.UUID); err != nil {
                warn(cl.Name, "сессии", err)
            } else {
                for _, s := range sessions {
                    cr.Sessions = append(cr.Sessions, sessionReport(s, ibByID, lic))
                }
            }
        }

        if lock {
            if locks, err := client.GetClusterLocks(ctx, cl.UUID); err != nil {
                warn(cl.Name, "блокировки", err)
            } else {
                for _, l := range locks {
                    cr.Locks = append(cr.Locks, LockReport{
                        Infobase: ibByID[l.InfobaseID], Description: l.Description,
                        SessionID: shortUUID(l.SessionID), ConnectionID: shortUUID(l.ConnectionID),
                        LockedAt: l.LockedAt,
                    })
                }
            }
        }

        // детали инфобаз
        var targets serialize.InfobaseSummaryList
        if *ibName != "" {
            if x, ok := ibList.ByName(*ibName); ok {
                targets = serialize.InfobaseSummaryList{x}
            } else {
                fmt.Fprintf(os.Stderr, "инфобаза %q не найдена в кластере\n", *ibName)
            }
        } else if dumpAllIB {
            targets = ibList
        }
        if len(targets) > 0 && *ibUser != "" {
            client.AuthenticateInfobase(cl.UUID, *ibUser, ibPassword)
        }
        for _, t := range targets {
            info, err := client.GetInfobaseInfo(ctx, cl.UUID, t.UUID)
            if err != nil {
                fmt.Fprintf(os.Stderr, "инфобаза %q: детали: %v (нужны -ib-user/-ib-password?)\n", t.Name, err)
                continue
            }
            cr.InfobaseDetails = append(cr.InfobaseDetails, InfobaseDetail{
                Name: info.Name, UUID: info.UUID.String(), Description: info.Description,
                Dbms: info.Dbms, DbServer: info.DbServer, DbName: info.DbName, DbUser: info.DbUser,
                SecurityLevel: info.SecurityLevel, Locale: info.Locale,
                SessionsDeny: info.SessionsDeny, ScheduledJobsDeny: info.ScheduledJobsDeny,
                DeniedMessage: info.DeniedMessage, SecurityProfile: info.SecurityProfileName,
            })
        }

        report.Clusters = append(report.Clusters, cr)
    }

    if *asJSON {
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(report); err != nil {
            fmt.Fprintf(os.Stderr, "ошибка JSON: %v\n", err)
            os.Exit(1)
        }
        return
    }
    printReport(report)
}

func sessionReport(s *serialize.SessionInfo, ibByID map[uuid.UUID]string, withLic bool) SessionReport {
    r := SessionReport{
        ID: s.ID, UUID: s.UUID.String(),
        Infobase: ibByID[s.InfobaseID], InfobaseID: s.InfobaseID.String(),
        User: s.UserName, Host: s.Host, App: s.AppId, ClientIP: s.ClientIPAddress,
        StartedAt: s.StartedAt, LastActiveAt: s.LastActiveAt,
    }
    if withLic && s.Licenses != nil {
        for _, l := range *s.Licenses {
            r.Licenses = append(r.Licenses, l.ShortPresentation)
        }
    }
    return r
}

func firstNonEmpty(vals ...string) string {
    for _, v := range vals {
        if v != "" {
            return v
        }
    }
    return ""
}

func shortUUID(u uuid.UUID) string {
    s := u.String()
    if s == "00000000-0000-0000-0000-000000000000" {
        return ""
    }
    return s[:8]
}

func warn(cluster, what string, err error) {
    fmt.Fprintf(os.Stderr, "кластер %s: %s: %v\n", cluster, what, err)
}

// writeLines записывает уникальные значения из set построчно (по алфавиту) в файл.
func writeLines(file string, set map[string]struct{}, label string) {
    vals := make([]string, 0, len(set))
    for v := range set {
        vals = append(vals, v)
    }
    sort.Strings(vals)
    var buf strings.Builder
    for _, v := range vals {
        buf.WriteString(v)
        buf.WriteByte('\n')
    }
    if err := os.WriteFile(file, []byte(buf.String()), 0o644); err != nil {
        fmt.Fprintf(os.Stderr, "не удалось записать %s: %v\n", file, err)
        os.Exit(1)
    }
    fmt.Printf("записано уникальных %s: %d → %s\n", label, len(vals), file)
}

// --- модель отчёта ---

type Report struct {
    Server      string          `json:"server"`
    RetrievedAt time.Time       `json:"retrieved_at"`
    Clusters    []ClusterReport `json:"clusters"`
}

type ClusterReport struct {
    UUID            string             `json:"uuid"`
    Name            string             `json:"name"`
    Host            string             `json:"host"`
    Port            int                `json:"port"`
    SecurityLevel   int                `json:"security_level"`
    Infobases       []InfobaseReport   `json:"infobases,omitempty"`
    Admins          []AdminReport      `json:"admins,omitempty"`
    Servers         []ServerReport     `json:"servers,omitempty"`
    Processes       []ProcessReport    `json:"processes,omitempty"`
    Connections     []ConnectionReport `json:"connections,omitempty"`
    Sessions        []SessionReport    `json:"sessions,omitempty"`
    Locks           []LockReport       `json:"locks,omitempty"`
    InfobaseDetails []InfobaseDetail   `json:"infobase_details,omitempty"`
}

type InfobaseReport struct {
    UUID        string `json:"uuid"`
    Name        string `json:"name"`
    Description string `json:"description,omitempty"`
}

type AdminReport struct {
    Name         string `json:"name"`
    Description  string `json:"description,omitempty"`
    PasswordAuth bool   `json:"password_auth"`
    OSAuth       bool   `json:"os_auth"`
    OSUser       string `json:"os_user,omitempty"`
}

type ServerReport struct {
    Name             string `json:"name"`
    AgentHost        string `json:"agent_host"`
    AgentPort        int    `json:"agent_port"`
    ClusterPort      int    `json:"cluster_port"`
    MainServer       bool   `json:"main_server"`
    PortRange        string `json:"port_range,omitempty"`
    ConnectionsLimit int    `json:"connections_limit"`
    InfobasesLimit   int    `json:"infobases_limit"`
}

type ProcessReport struct {
    Host          string    `json:"host"`
    Port          int       `json:"port"`
    Pid           string    `json:"pid"`
    Enable        bool      `json:"enable"`
    Running       bool      `json:"running"`
    MemoryKB      int       `json:"memory_kb"`
    Connections   int       `json:"connections"`
    AvailablePerf int       `json:"available_performance"`
    AvgCallTime   float64   `json:"avg_call_time"`
    StartedAt     time.Time `json:"started_at"`
}

type ConnectionReport struct {
    ID          int       `json:"id"`
    Host        string    `json:"host"`
    Application string    `json:"application"`
    Infobase    string    `json:"infobase,omitempty"`
    SessionID   int       `json:"session_id"`
    ConnectedAt time.Time `json:"connected_at"`
}

type SessionReport struct {
    ID           int       `json:"id"`
    UUID         string    `json:"uuid"`
    Infobase     string    `json:"infobase,omitempty"`
    InfobaseID   string    `json:"infobase_id"`
    User         string    `json:"user"`
    Host         string    `json:"host"`
    App          string    `json:"app"`
    ClientIP     string    `json:"client_ip"`
    StartedAt    time.Time `json:"started_at"`
    LastActiveAt time.Time `json:"last_active_at"`
    Licenses     []string  `json:"licenses,omitempty"`
}

type LockReport struct {
    Infobase     string    `json:"infobase,omitempty"`
    Description  string    `json:"description"`
    SessionID    string    `json:"session_id,omitempty"`
    ConnectionID string    `json:"connection_id,omitempty"`
    LockedAt     time.Time `json:"locked_at"`
}

type InfobaseDetail struct {
    Name              string `json:"name"`
    UUID              string `json:"uuid"`
    Description       string `json:"description,omitempty"`
    Dbms              string `json:"dbms"`
    DbServer          string `json:"db_server"`
    DbName            string `json:"db_name"`
    DbUser            string `json:"db_user"`
    SecurityLevel     int    `json:"security_level"`
    Locale            string `json:"locale"`
    SessionsDeny      bool   `json:"sessions_deny"`
    ScheduledJobsDeny bool   `json:"scheduled_jobs_deny"`
    DeniedMessage     string `json:"denied_message,omitempty"`
    SecurityProfile   string `json:"security_profile,omitempty"`
}

func printReport(r Report) {
    fmt.Printf("RAS %s  —  %s\n", r.Server, r.RetrievedAt.Format("2006-01-02 15:04:05"))
    for _, cl := range r.Clusters {
        fmt.Printf("\n=== Кластер: %s (%s)  %s:%d  уровень безопасности=%d ===\n",
            cl.Name, cl.UUID, cl.Host, cl.Port, cl.SecurityLevel)

        if len(cl.Infobases) > 0 {
            fmt.Printf("\nИнформационные базы (%d):\n", len(cl.Infobases))
            w := tw()
            fmt.Fprintln(w, "  ИМЯ\tОПИСАНИЕ\tUUID")
            for _, x := range cl.Infobases {
                fmt.Fprintf(w, "  %s\t%s\t%s\n", x.Name, x.Description, x.UUID)
            }
            w.Flush()
        }

        if len(cl.Admins) > 0 {
            fmt.Printf("\nАдминистраторы кластера (%d):\n", len(cl.Admins))
            w := tw()
            fmt.Fprintln(w, "  ИМЯ\tПАРОЛЬ.АУТ\tОС.АУТ\tОС-ПОЛЬЗОВАТЕЛЬ\tОПИСАНИЕ")
            for _, a := range cl.Admins {
                fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
                    a.Name, yesno(a.PasswordAuth), yesno(a.OSAuth), a.OSUser, a.Description)
            }
            w.Flush()
        }

        if len(cl.Servers) > 0 {
            fmt.Printf("\nРабочие серверы (%d):\n", len(cl.Servers))
            w := tw()
            fmt.Fprintln(w, "  ИМЯ\tЦЕНТР\tАГЕНТ\tКЛАСТЕР.ПОРТ\tДИАПАЗОН\tЛИМ.СОЕД\tЛИМ.БАЗ")
            for _, s := range cl.Servers {
                fmt.Fprintf(w, "  %s\t%s\t%s:%d\t%d\t%s\t%d\t%d\n",
                    s.Name, yesno(s.MainServer), s.AgentHost, s.AgentPort,
                    s.ClusterPort, s.PortRange, s.ConnectionsLimit, s.InfobasesLimit)
            }
            w.Flush()
        }

        if len(cl.Processes) > 0 {
            fmt.Printf("\nРабочие процессы rphost (%d):\n", len(cl.Processes))
            w := tw()
            fmt.Fprintln(w, "  ХОСТ\tPORT\tPID\tВКЛ\tРАБ\tПАМЯТЬ,МБ\tСОЕД\tДОСТ.ПРОИЗВ\tСР.ВЫЗОВ,с\tСТАРТ")
            for _, p := range cl.Processes {
                fmt.Fprintf(w, "  %s\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t%.3f\t%s\n",
                    p.Host, p.Port, p.Pid, yesno(p.Enable), yesno(p.Running),
                    p.MemoryKB/1024, p.Connections, p.AvailablePerf, p.AvgCallTime,
                    p.StartedAt.Format("2006-01-02 15:04"))
            }
            w.Flush()
        }

        if len(cl.Connections) > 0 {
            fmt.Printf("\nСоединения (%d):\n", len(cl.Connections))
            w := tw()
            fmt.Fprintln(w, "  ID\tПРИЛОЖЕНИЕ\tИНФОБАЗА\tХОСТ\tСЕССИЯ\tПОДКЛЮЧЕНО")
            for _, cn := range cl.Connections {
                fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%d\t%s\n",
                    cn.ID, cn.Application, cn.Infobase, cn.Host, cn.SessionID,
                    cn.ConnectedAt.Format("15:04:05"))
            }
            w.Flush()
        }

        if len(cl.Sessions) > 0 {
            fmt.Printf("\nСессии (%d):\n", len(cl.Sessions))
            w := tw()
            fmt.Fprintln(w, "  ID\tПОЛЬЗОВАТЕЛЬ\tИНФОБАЗА\tПРИЛОЖЕНИЕ\tХОСТ\tIP\tНАЧАЛО\tАКТИВНОСТЬ\tЛИЦЕНЗИИ")
            for _, s := range cl.Sessions {
                fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    s.ID, s.User, s.Infobase, s.App, s.Host, s.ClientIP,
                    s.StartedAt.Format("15:04:05"), s.LastActiveAt.Format("15:04:05"),
                    strings.Join(s.Licenses, "; "))
            }
            w.Flush()
        }

        if len(cl.Locks) > 0 {
            fmt.Printf("\nБлокировки (%d):\n", len(cl.Locks))
            w := tw()
            fmt.Fprintln(w, "  ИНФОБАЗА\tСЕССИЯ\tСОЕДИН\tКОГДА\tОПИСАНИЕ")
            for _, l := range cl.Locks {
                fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
                    l.Infobase, l.SessionID, l.ConnectionID, l.LockedAt.Format("15:04:05"), l.Description)
            }
            w.Flush()
        }

        for _, d := range cl.InfobaseDetails {
            fmt.Printf("\nИнфобаза «%s» (%s):\n", d.Name, d.UUID)
            fmt.Printf("  СУБД:           %s @ %s / %s (пользователь %s)\n", d.Dbms, d.DbServer, d.DbName, d.DbUser)
            fmt.Printf("  Безопасность:   уровень=%d, профиль=%s, locale=%s\n", d.SecurityLevel, d.SecurityProfile, d.Locale)
            fmt.Printf("  Блокировки:     сеансы=%s, регл.задания=%s\n", yesno(d.SessionsDeny), yesno(d.ScheduledJobsDeny))
            if d.DeniedMessage != "" {
                fmt.Printf("  Сообщение блок: %s\n", d.DeniedMessage)
            }
        }

        if len(cl.Infobases) == 0 && len(cl.Sessions) == 0 && len(cl.Admins) == 0 &&
            len(cl.Processes) == 0 && len(cl.Connections) == 0 && len(cl.Servers) == 0 &&
            len(cl.Locks) == 0 && len(cl.InfobaseDetails) == 0 {
            fmt.Println("  (нет данных — возможно, требуется -user/-password администратора кластера)")
        }
    }
}

func tw() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0) }

func yesno(b bool) string {
    if b {
        return "да"
    }
    return "нет"
}

