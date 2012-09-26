
{% wire id=#form
		type="submit"
 		postback=`vault_new`
 		delegate=`mod_vault` 
%}
<form id="{{ #form }}" action="postback">
	<p>{_ Create a new public/private key pair. _}</p>

	<label>{_ Key name _}</label>
	<input type="text" id="{{ #name }}" name="name" value="" />
	{% validate id=#name name="name" type={presence} %}

	<label>{_ Private key password _}</label>
	<input type="password" id="{{ #password }}" name="password" value="" />
	{% validate id=#password name="password" type={presence} %}

	<div class="modal-footer">
		{% button class="btn" action={dialog_close} text=_"Cancel" tag="a" %}
		<button class="btn btn-primary" type="submit">{_ Create Key _}</button>
	</div>
</form>
