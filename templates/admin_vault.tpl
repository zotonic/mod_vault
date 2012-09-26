{% extends "admin_base.tpl" %}

{% block title %}{_ Vault Keys _}{% endblock %}

{% block content %}

{% with m.vault.is_unlocked.vault as is_unlocked %}

<div class="edit-header">

	{% if is_unlocked %}
		{% wire id=#lock postback={vault_lock name=`vault`} delegate=`mod_vault` %}
	    <p class="pull-right">
	    	<a class="btn btn-small" id="{{ #lock }}" href="#lock">
	    		<i class="icon-lock"></i>
	    		{_ Lock Vault _}
		    </a><br/>
			<small><a href="{% url admin_vault %}">Manage keys &raquo;</a></small>
		</p>
	{% endif %}

    <h2>{_ Vault secure keys _}</h2>
    <p>{_ This is an overview of all the vault keys. _}</p>
</div>

{% if not is_unlocked %}

	<p class="alert">
		<i class="icon-lock"></i>
		{_ This page is locked. You need to enter your vault password to view the passwords. _}
	</p>

	{% wire id="donation-unlock" type="submit" postback={vault_unlock name=`vault`} delegate=`mod_vault` %}
	<form id="donation-unlock" class="form-inline" method="post" action="postback">
	<div class="control-group">
		<input type="password" placeholder="password" name="password" value="" />
		<input class="btn" type="submit" value="{_ Unlock _}" />
		<span class="help-inline error">{_ Wrong password. Try again. _}</span>
	</div>
	</form>
	<p><small><a href="{% url admin_vault %}">Manage keys &raquo;</a></small></p>

{% else %}

	<p>{% button class="btn" text=_"Add new key" action={dialog_open title=_"Add new key" template="_dialog_vault_new.tpl"} %}</p>


	<table class="table table-striped table-condensed">
	    <tr>
	        <th>{_ Name _}</th>
	        <th>{_ Owner _}</th>
	        <th>{_ Actions _}</th>
	    </tr>
	{% for d in m.vault.list_all_private %}
	{% with d.id as id %}
	    <tr id="vault-{{ id }}">
	        <td>
	        	{{ d.name|escape }}
	        </td>
	        <td>
	        	{{ d.user_id.title|default:"&ndash;" }}
	        </td>
	        <td class="actions">
	        	{% button class="btn btn-small" text=_"Copy"
		        		action={dialog_open title=_"Copy private key" template="_dialog_vault_copy.tpl" 
		        					user_id=d.user_id name=d.name}
	        	%}

	        	{% if d.user_id.is_editable and (d.user_id /= 1 or d.name /= "vault") %}
		        	{% button class="btn btn-small" text=_"Delete" 
		        			action={confirm
		        						text=_"Deleting a private key removes access to all encrypted data.<br/>Are you sure?"
		        						ok=_"Delete"
		        						postback={vault_delete id=id}
		        						delegate=`mod_vault`}
		        	%}
		        {% else %}
		        	{% button class="btn btn-small disabled" text=_"Delete" %}
		        {% endif %}

	        	{% if d.user_id.is_editable %}
		        	{% button class="btn btn-small" text=_"Change Password"
		        		action={dialog_open title=_"Change Password" template="_dialog_vault_password.tpl" 
		        					user_id=d.user_id name=d.name}
		        	%}
	        	{% else %}
		        	{% button class="btn btn-small disabled" text=_"Change Password" %}
		        {% endif %}
	        </td>
	     </tr>
	{% endwith %}
	{% endfor %}
	</table>

{% endif %}
{% endwith %}

{% endblock %}
