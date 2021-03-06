Feature: Sharing

	Background:
		Given these users exist:
		|username|password|displayname|email       |
		|user1   |1234    |User One   |u1@oc.com.np|
		|user2   |1234    |User Two   |u2@oc.com.np|
		|user3   |1234    |User Three |u2@oc.com.np|
		And these groups exist:
		|groupname|
		|grp1     |
		And the user "user1" is in the group "grp1"
		And the user "user2" is in the group "grp1"
		And I am on the login page
		And I login with username "user1" and password "1234"
		And I logout
		And I login with username "user2" and password "1234"

	Scenario: share a file & folder with another internal user
		And the folder "simple-folder" is shared with the user "User One"
		And the file "testimage.jpg" is shared with the user "User One"
		And I logout
		And I login with username "user1" and password "1234"
		Then the folder "simple-folder (2)" should be listed
		And the folder "simple-folder (2)" should be marked as shared by "User Two"
		And the file "testimage (2).jpg" should be listed
		And the file "testimage (2).jpg" should be marked as shared by "User Two"

	Scenario: share a folder with an internal group
		And I logout
		And I login with username "user3" and password "1234"
		And the folder "simple-folder" is shared with the group "grp1"
		And the file "testimage.jpg" is shared with the group "grp1"
		And I logout
		And I login with username "user1" and password "1234"
		Then the folder "simple-folder (2)" should be listed
		And the folder "simple-folder (2)" should be marked as shared with "grp1" by "User Three"
		And the file "testimage (2).jpg" should be listed
		And the file "testimage (2).jpg" should be marked as shared with "grp1" by "User Three"
		And I logout
		And I login with username "user2" and password "1234"
		Then the folder "simple-folder (2)" should be listed
		And the folder "simple-folder (2)" should be marked as shared with "grp1" by "User Three"
		And the file "testimage (2).jpg" should be listed
		And the file "testimage (2).jpg" should be marked as shared with "grp1" by "User Three"