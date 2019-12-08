/*
 * Copyright (c) 2005-2007 Atheme Development Group
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains protocol support for oftc-hybrid.
 *
 * $Id: oftc-hybrid.c 22 2007-09-20 19:26:07Z jilles $
 */

#include <atheme.h>
#include <atheme/protocol/oftc-hybrid.h>

/* *INDENT-OFF* */

static struct ircd OFTC_Hybrid = {
	.ircdname = "oftc-hybrid",
	.tldprefix = "$$",
	.uses_uid = true,
	.uses_rcommand = false,
	.uses_owner = false,
	.uses_protect = false,
	.uses_halfops = false,
	.uses_p10 = false,
	.uses_vhost = false,
	.oper_only_modes = 0,
	.owner_mode = 0,
	.protect_mode = 0,
	.halfops_mode = 0,
	.owner_mchar = "+",
	.protect_mchar = "+",
	.halfops_mchar = "+",
	.type = PROTOCOL_RATBOX,
	.perm_mode = 0,
	.oimmune_mode = 0,
	.ban_like_modes = "beIq",
	.except_mchar = 'e',
	.invex_mchar = 'I',
	.flags = IRCD_CIDR_BANS,
};

static const struct cmode oftc_hybrid_mode_list[] = {
  { 'i', CMODE_INVITE  },
  { 'm', CMODE_MOD     },
  { 'n', CMODE_NOEXT   },
  { 'p', CMODE_PRIV    },
  { 's', CMODE_SEC     },
  { 't', CMODE_TOPIC   },
  { 'c', CMODE_NOCOLOR },
  { 'R', CMODE_REGONLY },
  { 'z', CMODE_OPMOD   },
  { 'M', CMODE_MODREG  },
  { 'S', CMODE_SSLONLY },
  { '\0', 0 }
};

static struct extmode oftc_hybrid_ignore_mode_list[] = {
  { '\0', 0 }
};

static const struct cmode oftc_hybrid_status_mode_list[] = {
  { 'o', CSTATUS_OP    },
  { 'v', CSTATUS_VOICE },
  { '\0', 0 }
};

static const struct cmode oftc_hybrid_prefix_mode_list[] = {
  { '@', CSTATUS_OP    },
  { '+', CSTATUS_VOICE },
  { '\0', 0 }
};

static const struct cmode oftc_hybrid_user_mode_list[] = {
  { 'S', UF_IMMUNE  },
  { 'a', UF_ADMIN   },
  { 'i', UF_INVIS   },
  { 'o', UF_IRCOP   },
  { 'D', UF_DEAF    },
  { 'P', UF_SERVICE },
  { '\0', 0 }
};

static bool use_tburst = false;

/* *INDENT-ON* */

/* login to our uplink */
static unsigned int
oftc_hybrid_server_login(void)
{
	int ret = 1;

	if (!me.numeric)
	{
		ircd->uses_uid = false;
		ret = sts("PASS %s :TS", curr_uplink->send_pass);
	}
	else if (strlen(me.numeric) == 3 && isdigit((unsigned char)*me.numeric))
	{
		ircd->uses_uid = true;
		ret = sts("PASS %s TS 6 :%s", curr_uplink->send_pass, me.numeric);
	}
	else
	{
		slog(LG_ERROR, "Invalid numeric (SID) %s", me.numeric);
	}
	if (ret == 1)
		return 1;

	me.bursting = true;

	sts("CAPAB :QS EX IE KLN UNKLN ENCAP TB TBURST QUIET EOB");
	sts("SERVER %s 1 :%s%s", me.name, me.hidden ? "(H) " : "", me.desc);
	sts("SVINFO %d 3 0 :%lu", ircd->uses_uid ? 6 : 5,
			(unsigned long)CURRTIME);

	return 0;
}

static void
oftc_hybrid_introduce_nick(struct user *u)
{
	const char *umode = user_get_umodestr(u);

	sts(":%s UID %s 1 %lu %s %s %s 0 %s :%s", me.numeric, u->nick, (unsigned long)u->ts, umode, u->user, u->host, u->uid, u->gecos);
}

/* WALLOPS wrapper */
static void
oftc_hybrid_wallops_sts(const char *text)
{
	/* Generate +s server notice -- jilles */
	sts(":%s GNOTICE %s 1 :%s", ME, me.name, text);
}

static void
oftc_hybrid_notice_channel_sts(struct user *from, struct channel *target, const char *text)
{
	sts(":%s NOTICE %s :%s", from ? CLIENT_NAME(from) : ME, target->name, text);
}

static void
oftc_hybrid_kline_sts(const char *server, const char *user, const char *host, long duration, const char *reason)
{
	struct service *svs;

	svs = service_find("operserv");
	sts(":%s KLINE %s %ld %s %s :autokilled: %s", svs != NULL ? CLIENT_NAME(svs->me) : ME, server, duration, user, host, reason);
}

static void
oftc_hybrid_unkline_sts(const char *server, const char *user, const char *host)
{
	struct service *svs;

	svs = service_find("operserv");
	sts(":%s UNKLINE %s %s %s", svs != NULL ? CLIENT_NAME(svs->me) : ME, server, user, host);
}

static void
oftc_hybrid_xline_sts(const char *server, const char *realname, long duration, const char *reason)
{
	struct service *svs;

	svs = service_find("operserv");
	sts(":%s ENCAP %s XLINE %s %s %ld :%s", svs != NULL ? CLIENT_NAME(svs->me) : ME, server, server, realname, duration, reason);
}

static void
oftc_hybrid_unxline_sts(const char *server, const char *realname)
{
	struct service *svs;

	svs = service_find("operserv");
	sts(":%s UNXLINE %s %s", svs != NULL ? CLIENT_NAME(svs->me) : ME, server, realname);
}

static void
oftc_hybrid_unqline_sts(const char *server, const char *name)
{
	struct service *svs;

	svs = service_find("operserv");
	sts(":%s UNRESV %s %s", svs != NULL ? CLIENT_NAME(svs->me) : ME, server, name);
}

/* topic wrapper */
static void
oftc_hybrid_topic_sts(struct channel *c, struct user *source, const char *setter, time_t ts, time_t prevts, const char *topic)
{
	int joined = 0;

	return_if_fail(c != NULL);
	return_if_fail(source != NULL);

	if (use_tburst && (c->ts > 0 || ts > prevts + SECONDS_PER_MINUTE))
	{
		/* send a channel TS of 0 to force our change to take */
		sts(":%s TBURST 0 %s %lu %s :%s", ME, c->name, (unsigned long)ts, setter, topic);
		return;
	}
	/* We have to be on channel to change topic.
	 * We cannot nicely change topic from the server:
	 * :server.name TOPIC doesn't propagate and TB requires
	 * us to specify an older topicts.
	 * -- jilles
	 */
	if (!chanuser_find(c, source))
	{
		sts(":%s SJOIN %lu %s + :@%s", ME, (unsigned long)c->ts, c->name, CLIENT_NAME(source));
		joined = 1;
	}
	sts(":%s TOPIC %s :%s", CLIENT_NAME(source), c->name, topic);
	if (joined)
		sts(":%s PART %s :Topic set for %s",
				CLIENT_NAME(source), c->name, setter);
	c->topicts = CURRTIME;
}

/* protocol-specific stuff to do on login */
static void
oftc_hybrid_on_login(struct user *u, struct myuser *mu, const char *wantedhost)
{
	return_if_fail(u != NULL);

	/* set +R if they're identified to the nick they are using */
	if (should_reg_umode(u))
		sts(":%s SVSMODE %s +R", ME, CLIENT_NAME(u));
}

/* protocol-specific stuff to do on login */
static bool
oftc_hybrid_on_logout(struct user *u, const char *account)
{
	return_val_if_fail(u != NULL, false);

	if (!nicksvs.no_nick_ownership)
		sts(":%s SVSMODE %s -R", ME, CLIENT_NAME(u));

	return false;
}

static void
oftc_hybrid_fnc_sts(struct user *source, struct user *u, const char *newnick, int type)
{
	sts(":%s SVSNICK %s %s", CLIENT_NAME(source), CLIENT_NAME(u), newnick);
}

static void
oftc_hybrid_sethost_sts(struct user *source, struct user *target, const char *host)
{
	sts(":%s SVSCLOAK %s :%s", ME, CLIENT_NAME(target), host);
}

static void
oftc_hybrid_holdnick_sts(struct user *source, int duration, const char *nick, struct myuser *mu)
{
	if (duration == 0)
		return; /* can't do this safely */
	sts(":%s ENCAP * RESV %d %s 0 :Reserved by %s for nickname owner (%s)",
			CLIENT_NAME(source), duration > 300 ? 300 : duration,
			nick, source->nick,
			mu ? entity(mu)->name : nick);
}

static void
m_tburst(struct sourceinfo *si, int parc, char *parv[])
{
	struct channel *c = channel_find(parv[1]);
	time_t channelts;
	time_t topicts;

	if (c == NULL)
		return;

	/* Our uplink is trying to change the topic during burst,
	 * and we have already set a topic. Assume our change won.
	 * -- jilles */
	if (si->s != NULL && si->s->uplink == me.me &&
			!(si->s->flags & SF_EOB) && c->topic != NULL)
		return;

	channelts = atol(parv[0]);
	topicts = atol(parv[2]);
	if (c->topic == NULL || channelts < c->ts || (channelts == c->ts && topicts > c->topicts))
		handle_topic_from(si, c, parv[3], topicts, parv[parc - 1]);
}

static void
m_pong(struct sourceinfo *si, int parc, char *parv[])
{
	struct server *s;

	// someone replied to our PING
	if (!parv[0])
		return;
	s = server_find(parv[0]);
	if (s == NULL)
		return;
	handle_eob(s);

	if (s != si->s)
		return;

	me.uplinkpong = CURRTIME;

	// -> :test.projectxero.net PONG test.projectxero.net :shrike.malkier.net
	if (me.bursting)
	{
#ifdef HAVE_GETTIMEOFDAY
		e_time(burstime, &burstime);

		slog(LG_INFO, "m_pong(): finished synching with uplink (%d %s)", (tv2ms(&burstime) > 1000) ? (tv2ms(&burstime) / 1000) : tv2ms(&burstime), (tv2ms(&burstime) > 1000) ? "s" : "ms");

		wallops("Finished synchronizing with network in %d %s.", (tv2ms(&burstime) > 1000) ? (tv2ms(&burstime) / 1000) : tv2ms(&burstime), (tv2ms(&burstime) > 1000) ? "s" : "ms");
#else
		slog(LG_INFO, "m_pong(): finished synching with uplink");
		wallops("Finished synchronizing with network.");
#endif

		me.bursting = false;
		// Send EOB here?
	}
}

static void
m_nick(struct sourceinfo *si, int parc, char *parv[])
{
	struct server *s;
	struct user *u;
	bool realchange;

	// got the right number of args for an introduction?
	if (parc == 8)
	{
		s = server_find(parv[6]);
		if (!s)
		{
			slog(LG_DEBUG, "m_nick(): new user on nonexistent server: %s", parv[6]);
			return;
		}

		slog(LG_DEBUG, "m_nick(): new user on `%s': %s", s->name, parv[0]);

		u = user_add(parv[0], parv[4], parv[5], NULL, NULL, NULL, parv[7], s, atoi(parv[2]));
		if (u == NULL)
			return;

		user_mode(u, parv[3]);
		if (strchr(parv[3], 'P'))
			u->flags |= UF_IMMUNE;

		// umode +R: identified to current nick
		if (strchr(parv[3], 'R'))
			handle_burstlogin(u, NULL, 0);

		/* If server is not yet EOB we will do this later.
		 * This avoids useless "please identify" -- jilles */
		if (s->flags & SF_EOB)
			handle_nickchange(user_find(parv[0]));
	}

	// if it's only 2 then it's a nickname change
	else if (parc == 2)
	{
		if (!si->su)
		{
			slog(LG_DEBUG, "m_nick(): server trying to change nick: %s", si->s != NULL ? si->s->name : "<none>");
			return;
		}

		slog(LG_DEBUG, "m_nick(): nickname change from `%s': %s", si->su->nick, parv[0]);

		realchange = irccasecmp(si->su->nick, parv[0]);

		if (user_changenick(si->su, parv[0], atoi(parv[1])))
			return;

		/* fix up +R if necessary -- jilles */
		if (realchange && should_reg_umode(si->su))
			/* changed nick to registered one, reset +R */
			sts(":%s SVSMODE %s +R", ME, CLIENT_NAME(si->su));

		/* It could happen that our PING arrived late and the
		 * server didn't acknowledge EOB yet even though it is
		 * EOB; don't send double notices in that case -- jilles */
		if (si->su->server->flags & SF_EOB)
			handle_nickchange(si->su);
	}
	else
	{
		int i;
		slog(LG_DEBUG, "m_nick(): got NICK with wrong number of params");

		for (i = 0; i < parc; i++)
			slog(LG_DEBUG, "m_nick():   parv[%d] = %s", i, parv[i]);
	}
}

static void
m_uid(struct sourceinfo *si, int parc, char *parv[])
{
	struct server *s;
	struct user *u;

	// got the right number of args for an introduction?
	if (parc == 9)
	{
		s = si->s;
		slog(LG_DEBUG, "m_uid(): new user on `%s': %s", s->name, parv[0]);

		u = user_add(parv[0], parv[4], parv[5], NULL, parv[6], parv[7], parv[8], s, atoi(parv[2]));
		if (u == NULL)
			return;

		user_mode(u, parv[3]);
		if (strchr(parv[3], 'P'))
			u->flags |= UF_IMMUNE;

		/* umode +R: identified to current nick */
		if (strchr(parv[3], 'R'))
			handle_burstlogin(u, NULL, 0);

		/* If server is not yet EOB we will do this later.
		 * This avoids useless "please identify" -- jilles
		 */
		if (s->flags & SF_EOB)
			handle_nickchange(user_find(parv[0]));
	}
	else
	{
		int i;
		slog(LG_DEBUG, "m_uid(): got UID with wrong number of params");

		for (i = 0; i < parc; i++)
			slog(LG_DEBUG, "m_uid():   parv[%d] = %s", i, parv[i]);
	}
}

static void
m_capab(struct sourceinfo *si, int parc, char *parv[])
{
	char *p;

	use_tburst = false;
	for (p = strtok(parv[0], " "); p != NULL; p = strtok(NULL, " "))
	{
		if (!irccasecmp(p, "TBURST"))
		{
			slog(LG_DEBUG, "m_capab(): uplink does Hybrid-style topic bursting, using if appropriate.");
			use_tburst = true;
		}
	}

	/* Now we know whether or not we should enable services support,
	 * so burst the clients.
	 *	 --nenolod
	 */
	services_init();
}

static void
m_realhost(struct sourceinfo *si, int parc, char *parv[])
{
	struct user *u = user_find(parv[0]);

	if (!u)
		return;

	strshare_unref(u->host);
	u->host = strshare_get(parv[1]);
}

static void
m_certfp(struct sourceinfo *si, int parc, char *parv[])
{
	struct user *u = user_find(parv[0]);

	if (u == NULL)
		return;

	handle_certfp(si, u, parv[2]);
}

static void
nick_group(struct hook_user_req *hdata)
{
	struct user *u;

	u = hdata->si->su != NULL && !irccasecmp(hdata->si->su->nick, hdata->mn->nick) ? hdata->si->su : user_find_named(hdata->mn->nick);
	if (u != NULL && should_reg_umode(u))
		sts(":%s SVSMODE %s +R", ME, CLIENT_NAME(u));
}

static void
nick_ungroup(struct hook_user_req *hdata)
{
	struct user *u;

	u = hdata->si->su != NULL && !irccasecmp(hdata->si->su->nick, hdata->mn->nick) ? hdata->si->su : user_find_named(hdata->mn->nick);
	if (u != NULL && !nicksvs.no_nick_ownership)
		sts(":%s SVSMODE %s -R", ME, CLIENT_NAME(u));
}

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "protocol/ts6-generic")

	mode_list = oftc_hybrid_mode_list;
	ignore_mode_list = oftc_hybrid_ignore_mode_list;
	status_mode_list = oftc_hybrid_status_mode_list;
	prefix_mode_list = oftc_hybrid_prefix_mode_list;
	user_mode_list = oftc_hybrid_user_mode_list;
	ignore_mode_list_size = ARRAY_SIZE(oftc_hybrid_ignore_mode_list);

	ircd = &OFTC_Hybrid;

	/* Symbol relocation voodoo. */
	server_login = &oftc_hybrid_server_login;
	introduce_nick = &oftc_hybrid_introduce_nick;
	wallops_sts = &oftc_hybrid_wallops_sts;
	notice_channel_sts = &oftc_hybrid_notice_channel_sts;
	kline_sts = &oftc_hybrid_kline_sts;
	unkline_sts = &oftc_hybrid_unkline_sts;
	xline_sts = &oftc_hybrid_xline_sts;
	unxline_sts = &oftc_hybrid_unxline_sts;
	unqline_sts = &oftc_hybrid_unqline_sts;
	dline_sts = &generic_dline_sts;
	undline_sts = &generic_undline_sts;
	topic_sts = &oftc_hybrid_topic_sts;
	ircd_on_login = &oftc_hybrid_on_login;
	ircd_on_logout = &oftc_hybrid_on_logout;
	fnc_sts = &oftc_hybrid_fnc_sts;
	holdnick_sts = &oftc_hybrid_holdnick_sts;
	sethost_sts = &oftc_hybrid_sethost_sts;
	svslogin_sts = &generic_svslogin_sts;
	sasl_sts = &generic_sasl_sts;
	sasl_mechlist_sts = &generic_sasl_mechlist_sts;
	mlock_sts = &generic_mlock_sts;

	pcommand_add("TBURST", m_tburst, 5, MSRC_SERVER);
	pcommand_delete("PONG");
	pcommand_add("PONG", m_pong, 1, MSRC_SERVER);
	pcommand_delete("NICK");
	pcommand_add("NICK", m_nick, 2, MSRC_USER | MSRC_SERVER);
	pcommand_delete("UID");
	pcommand_add("UID", m_uid, 9, MSRC_SERVER);
	pcommand_delete("CAPAB");
	pcommand_add("CAPAB", m_capab, 1, MSRC_UNREG);
	pcommand_add("REALHOST", m_realhost, 2, MSRC_SERVER);
	pcommand_add("CERTFP", m_certfp, 2, MSRC_SERVER);

	hook_add_nick_group(nick_group);
	hook_add_nick_ungroup(nick_ungroup);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{

}

SIMPLE_DECLARE_MODULE_V1("protocol/hybrid", MODULE_UNLOAD_CAPABILITY_NEVER);
