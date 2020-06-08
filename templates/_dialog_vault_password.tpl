
{% wire id=#form
		type="submit"
 		postback={vault_password name=name user_id=user_id}
 		delegate=`mod_vault` 
%}
<form id="{{ #form }}" class="form" action="postback">
	<p>{_ Change the password of the key: _} <strong>{{ name|escape }}</strong> ({{ user_id.title }})</p>

	<div class="form-group">
		<label>{_ Old password _}</label>
		<input type="password" id="{{ #old }}" name="old" value="" class="form-control">
		{% validate id=#old name="old" type={presence} %}
	</div>

	<div class="form-group">
		<label>{_ New password _}</label>
		<input type="password" id="{{ #new }}" name="new" value="" class="form-control">
		{% validate id=#new name="new" type={presence} %}
	</div>

	<div class="modal-footer">
		{% button class="btn btn-default" action={dialog_close} text=_"Cancel" tag="a" %}
		<button class="btn btn-primary" type="submit">{_ Change Password _}</button>
	</div>
</form>
