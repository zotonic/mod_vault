
{% wire id=#form
		type="submit"
 		postback={vault_copy name=name user_id=user_id}
 		delegate=`mod_vault`
%}
<form id="{{ #form }}" action="postback">
	<p>{_ Copy the key: _} <strong>{{ name|escape }}</strong> ({{ user_id.title }})</p>

	<label>{_ Password _}</label>
	<input type="password" id="{{ #old }}" name="old" value="" />
	{% validate id=#old name="old" type={presence} %}

	<label>{_ To user _}</label>
	<input type="text" id="{{ #user }}" name="username" value="" />
	{% validate id=#user name="username" type={presence} %}

	<label>{_ New password _}</label>
	<input type="password" id="{{ #new }}" name="new" value="" />
	{% validate id=#new name="new" type={presence} %}

	<div class="modal-footer">
		{% button class="btn" action={dialog_close} text=_"Cancel" tag="a" %}
		<button class="btn btn-primary" type="submit">{_ Copy Private Key _}</button>
	</div>
</form>
