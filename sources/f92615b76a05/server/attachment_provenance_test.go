package server

import "testing"

func TestBetaAttachmentProvenance(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	s := &Server{jwtKey: []byte("synthetic-test-key-with-at-least-32-bytes")}
	target, other := int64(3), int64(4)
	attachment := chatAttachment{Name: "proof.txt", Path: "/home/test/uploads/proof.txt", Abs: "/home/test/uploads/proof.txt", Size: 5}
	attachment.Token = s.attachmentToken(2, target, attachment)
	if !s.validUploadedAttachments(2, &target, []chatAttachment{attachment}) {
		t.Fatal("valid upload rejected")
	}
	if s.validUploadedAttachments(9, &target, []chatAttachment{attachment}) || s.validUploadedAttachments(2, &other, []chatAttachment{attachment}) || s.validUploadedAttachments(2, nil, []chatAttachment{attachment}) {
		t.Fatal("foreign upload accepted")
	}
	for _, mutate := range []func(*chatAttachment){
		func(a *chatAttachment) { a.Path = "/private/key" },
		func(a *chatAttachment) { a.Abs = "/private/key" },
		func(a *chatAttachment) { a.Name = "other.txt" },
		func(a *chatAttachment) { a.Size++ },
		func(a *chatAttachment) { a.Token = "" },
	} {
		changed := attachment
		mutate(&changed)
		if s.validUploadedAttachments(2, &target, []chatAttachment{changed}) {
			t.Fatal("modified upload accepted")
		}
	}
}
